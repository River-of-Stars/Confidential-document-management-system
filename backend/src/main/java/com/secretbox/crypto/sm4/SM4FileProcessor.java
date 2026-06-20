package com.secretbox.crypto.sm4;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.secretbox.crypto.exception.CryptoException;
import com.secretbox.crypto.sm3.SM3Util;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

/**
 * SM4 文件分片处理器
 * 核心功能：
 * 1. 大文件分片加密：边读边加密，明文不落地
 * 2. 大文件分片解密：边读边解密，支持流式输出
 * 3. 文件加密后附带SM3校验值，用于完整性校验
 * 
 * 内存优化：每次只处理一个分片（默认8MB），适合低配硬件（4G内存）
 */
@Slf4j
@Component
public class SM4FileProcessor {
    
    @Autowired
    private SM3Util sm3Util;
    
    // 分片大小：8MB，平衡内存与性能
    private static final int CHUNK_SIZE = 8 * 1024 * 1024;
    private static final int IV_LENGTH = 16;
    private static final String ENCRYPTED_FILE_EXTENSION = ".sm4";
    private static final String META_FILE_EXTENSION = ".meta";
    
    /**
     * 加密文件（分片处理，明文不落地）
     * 
     * @param sourceFilePath 源文件路径
     * @param keyBase64 SM4密钥（Base64编码）
     * @param outputDir 输出目录（加密文件存放位置）
     * @return 加密文件信息（包含文件路径、SM3哈希、IV）
     * @throws CryptoException 文件不存在、密钥无效或IO异常时抛出
     */
    public EncryptedFileInfo encryptFile(String sourceFilePath, String keyBase64, String outputDir) {
        if (sourceFilePath == null || sourceFilePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "源文件路径不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }
        
        Path sourcePath = Paths.get(sourceFilePath);
        if (!Files.exists(sourcePath)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, 
                "源文件不存在: " + sourceFilePath);
        }
        
        try {
            // 确保输出目录存在
            File outputDirFile = new File(outputDir);
            if (!outputDirFile.exists()) {
                outputDirFile.mkdirs();
            }
            
            // 生成随机IV
            byte[] ivBytes = new byte[IV_LENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(ivBytes);
            String ivBase64 = Base64.encode(ivBytes);
            
            // 输出文件路径
            String fileName = sourcePath.getFileName().toString();
            String encryptedFilePath = outputDir + File.separator + fileName + ENCRYPTED_FILE_EXTENSION;
            String metaFilePath = outputDir + File.separator + fileName + META_FILE_EXTENSION;
            
            // 创建SM4加密器
            SymmetricCrypto sm4 = SmUtil.sm4(Base64.decode(keyBase64), ivBytes);
            
            // 分片加密并写入文件
            long fileSize = 0;
            long encryptedSize = 0;
            
            try (InputStream inputStream = Files.newInputStream(sourcePath);
                 OutputStream outputStream = Files.newOutputStream(Paths.get(encryptedFilePath));
                 ByteArrayOutputStream metaOutputStream = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    fileSize += bytesRead;
                    
                    // 只加密实际读取的有效数据
                    byte[] chunkData;
                    if (bytesRead < CHUNK_SIZE) {
                        chunkData = new byte[bytesRead];
                        System.arraycopy(buffer, 0, chunkData, 0, bytesRead);
                    } else {
                        chunkData = buffer;
                    }
                    
                    // 加密分片
                    byte[] encryptedChunk = sm4.encrypt(chunkData);
                    encryptedSize += encryptedChunk.length;
                    
                    // 写入加密数据
                    outputStream.write(encryptedChunk);
                }
            }
            
            // 计算加密文件的SM3哈希（用于完整性校验）
            String fileHash = sm3Util.hashFile(encryptedFilePath);
            
            // 保存元数据
            EncryptedFileInfo info = new EncryptedFileInfo();
            info.setOriginalFileName(fileName);
            info.setEncryptedFilePath(encryptedFilePath);
            info.setMetaFilePath(metaFilePath);
            info.setIv(ivBase64);
            info.setFileHash(fileHash);
            info.setOriginalSize(fileSize);
            info.setEncryptedSize(encryptedSize);
            info.setKeyId(extractKeyId(keyBase64));
            
            // 保存元数据到文件
            saveMetaData(metaFilePath, info);
            
            log.info("文件加密成功: {}, 原大小: {} bytes, 加密大小: {} bytes", 
                fileName, fileSize, encryptedSize);
            
            return info;
            
        } catch (IOException e) {
            log.error("文件加密IO异常: {}", sourceFilePath, e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "文件加密失败: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("文件加密失败: {}", sourceFilePath, e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "文件加密失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 解密文件（分片处理，流式输出）
     * 
     * @param encryptedFilePath 加密文件路径
     * @param keyBase64 SM4密钥（Base64编码）
     * @param outputDir 输出目录（解密文件存放位置）
     * @return 解密后的文件路径
     * @throws CryptoException 文件损坏、密钥错误或完整性校验失败时抛出
     */
    public String decryptFile(String encryptedFilePath, String keyBase64, String outputDir) {
        if (encryptedFilePath == null || encryptedFilePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "加密文件路径不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }
        
        Path encryptedPath = Paths.get(encryptedFilePath);
        if (!Files.exists(enc