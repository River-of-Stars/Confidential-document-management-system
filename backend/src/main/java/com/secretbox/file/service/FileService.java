package com.secretbox.file.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.secretbox.crypto.sm3.SM3Util;
import com.secretbox.crypto.sm4.SM4Util;
import com.secretbox.file.entity.FileMetadata;
import com.secretbox.file.enums.FileClassification;
import com.secretbox.file.mapper.FileMetadataMapper;
import com.secretbox.file.model.FileUploadResponse;
import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import com.secretbox.auth.model.SecretBoxUserDetails;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Date;
import java.util.UUID;
import cn.hutool.core.codec.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class FileService {

    private final MinioClient minioClient;
    private final FileMetadataMapper fileMetadataMapper;
    private final SM4Util sm4Util;
    private final SM3Util sm3Util;

    @Value("${minio.bucket-name}")
    private String bucketName;

    /**
     * 上传文件：内存加密，存入MinIO，保存元数据
     */
    @Transactional
    public FileUploadResponse uploadFile(MultipartFile file, Integer classificationLevel) throws Exception {
        // 获取当前用户
        SecretBoxUserDetails userDetails = (SecretBoxUserDetails) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();

        // 读取文件字节（内存）
        byte[] plainBytes = file.getBytes();

        // 计算原文件SM3哈希（用于完整性校验）
        String originalHash = sm3Util.hashBytes(plainBytes);

        // 生成独立SM4密钥
        String keyBase64 = sm4Util.generateKey();

        // 加密文件（内存）
        String encryptedData = sm4Util.encryptBytes(plainBytes, keyBase64, null);
        // 加密数据格式: IV_BASE64:CIPHER_BASE64，我们拆分获取密文
        String[] parts = encryptedData.split(":");
        String ivBase64 = parts[0];   
        byte[] cipherBytes = cn.hutool.core.codec.Base64.decode(parts[1]);

        // 上传到MinIO
        String objectName = UUID.randomUUID().toString();
        String contentType = file.getContentType();

        try (ByteArrayInputStream bais = new ByteArrayInputStream(cipherBytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectName)
                            .stream(bais, cipherBytes.length, -1)
                            .contentType(contentType)
                            .build()
            );
        }

        // 保存元数据
        FileMetadata metadata = new FileMetadata();
        metadata.setFileName(file.getOriginalFilename());
        metadata.setFileSize(file.getSize());
        metadata.setUploader(userDetails.getUsername());
        metadata.setUploaderName(userDetails.getRealName());
        metadata.setUploadTime(new Date());
        metadata.setClassification(classificationLevel != null ? classificationLevel : FileClassification.INTERNAL.getLevel());
        metadata.setSm3Hash(originalHash);
        metadata.setMinioObjectName(objectName);
        metadata.setIv(ivBase64); 
        metadata.setEncryptKey(keyBase64);  // 实际生产需加密存储
        metadata.setContentType(contentType);
        fileMetadataMapper.insert(metadata);

        log.info("文件上传成功: {}, 对象名: {}", file.getOriginalFilename(), objectName);

        FileUploadResponse response = new FileUploadResponse();
        response.setFileId(metadata.getId());
        response.setFileName(metadata.getFileName());
        response.setUploadTime(metadata.getUploadTime());
        return response;
    }

    /**
     * 下载文件：校验权限，从MinIO获取密文，解密后返回流
     */
    public InputStream downloadFile(Long fileId) throws Exception {
    FileMetadata metadata = fileMetadataMapper.selectById(fileId);
    if (metadata == null) {
        throw new RuntimeException("文件不存在");
    }
    checkPermission(metadata);
    
    log.info("开始下载文件，fileId: {}, objectName: {}, iv: {}", fileId, metadata.getMinioObjectName(), metadata.getIv());
    
    // 从MinIO获取对象
    InputStream minioStream = null;
    try {
        minioStream = minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(bucketName)
                        .object(metadata.getMinioObjectName())
                        .build()
        );
    } catch (Exception e) {
        log.error("从MinIO获取对象失败", e);
        throw new RuntimeException("从MinIO下载文件失败: " + e.getMessage(), e);
    }
    
    if (minioStream == null) {
        throw new RuntimeException("MinIO返回空流，文件可能不存在");
    }
    
    // 读取密文到内存
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int len;
    try {
        while ((len = minioStream.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
    } catch (Exception e) {
        log.error("读取密文流失败", e);
        throw new RuntimeException("读取密文失败", e);
    } finally {
        minioStream.close();
    }
    byte[] cipherBytes = baos.toByteArray();
    log.info("密文大小: {}", cipherBytes.length);
    
    // 检查IV是否为空
    if (metadata.getIv() == null || metadata.getIv().isEmpty()) {
        throw new RuntimeException("文件加密IV缺失，无法解密");
    }
    
    // 解密
    String encryptedData = metadata.getIv() + ":" + Base64.encode(cipherBytes);
    byte[] plainBytes = sm4Util.decryptBytes(encryptedData, metadata.getEncryptKey());
    log.info("解密成功，明文大小: {}", plainBytes.length);
    
    return new ByteArrayInputStream(plainBytes);
}

    // 权限校验方法
    private void checkPermission(FileMetadata metadata) {
        SecretBoxUserDetails user = (SecretBoxUserDetails) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        String role = user.getRoleCode();
        String department = user.getDepartment();
        // 超级管理员：全权限
        if ("SUPER_ADMIN".equals(role)) {
            return;
        }
        // 部门保密员：可访问本部门文件（需要部门匹配）和公开文件
        if ("DEPT_SECRETARY".equals(role)) {
            // 若文件密级为公开，允许
            if (metadata.getClassification() == FileClassification.PUBLIC.getLevel()) {
                return;
            }
            // 若文件上传人所在部门与当前用户相同，允许（这里需要关联用户部门，但文件元数据无部门，可通过上传人查用户）
            // 简化：仅根据文件密级和角色控制，不实现部门匹配
            // 但为了演示，我们允许保密员访问所有内部及以上，但一般应限制部门
            // 这里仅做示范，若密级 <= 秘密，允许保密员访问
            if (metadata.getClassification() <= FileClassification.SECRET.getLevel()) {
                return;
            }
            throw new RuntimeException("权限不足，您不是本部门保密员或密级过高");
        }
        // 普通员工：只能访问自己上传的文件和公开文件
        if ("EMPLOYEE".equals(role)) {
            if (metadata.getClassification() == FileClassification.PUBLIC.getLevel()) {
                return;
            }
            if (metadata.getUploader().equals(user.getUsername())) {
                return;
            }
            throw new RuntimeException("权限不足，您只能访问自己上传的文件或公开文件");
        }
        throw new RuntimeException("权限不足");
    }

    // 删除文件
    @Transactional
    public void deleteFile(Long fileId) {
        FileMetadata metadata = fileMetadataMapper.selectById(fileId);
        if (metadata == null) {
            throw new RuntimeException("文件不存在");
        }
        // 校验权限：仅上传人或管理员可删除
        SecretBoxUserDetails user = (SecretBoxUserDetails) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        if (!"SUPER_ADMIN".equals(user.getRoleCode()) && !metadata.getUploader().equals(user.getUsername())) {
            throw new RuntimeException("权限不足，仅上传人或管理员可删除");
        }
        // 删除MinIO对象
        try {
            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(bucketName)
                            .object(metadata.getMinioObjectName())
                            .build()
            );
        } catch (Exception e) {
            log.error("删除MinIO对象失败", e);
            throw new RuntimeException("文件删除失败", e);
        }
        // 删除元数据（密钥随之丢弃）
        fileMetadataMapper.deleteById(fileId);
        log.info("文件删除成功: {}", metadata.getFileName());
    }
}