package com.secretbox.crypto.sm4;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.FileUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.json.JSONUtil;
import com.secretbox.crypto.exception.CryptoException;
import com.secretbox.crypto.sm3.SM3Util;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

@Slf4j
@Component
@RequiredArgsConstructor
public class SM4FileProcessor {

    private final SM3Util sm3Util;

    private static final int CHUNK_SIZE = 8 * 1024 * 1024;
    private static final int IV_LENGTH = 16;
    private static final String ALGORITHM = "SM4/CBC/PKCS5Padding";
    private static final String ENCRYPTED_EXT = ".sm4";
    private static final String META_EXT = ".meta";

    public EncryptedFileInfo encryptFile(String sourceFilePath, String keyBase64, String outputDir) {
        if (sourceFilePath == null || sourceFilePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "源文件路径不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }

        Path sourcePath = Paths.get(sourceFilePath);
        if (!Files.exists(sourcePath)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "源文件不存在: " + sourceFilePath);
        }

        try {
            File outputDirFile = new File(outputDir);
            if (!outputDirFile.exists()) {
                outputDirFile.mkdirs();
            }

            byte[] ivBytes = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(ivBytes);
            String ivBase64 = Base64.encode(ivBytes);

            byte[] keyBytes = Base64.decode(keyBase64);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, keySpec, ivSpec);

            String fileName = sourcePath.getFileName().toString();
            String encryptedFilePath = outputDir + File.separator + fileName + ENCRYPTED_EXT;
            String metaFilePath = outputDir + File.separator + fileName + META_EXT;

            long originalSize = 0;
            long encryptedSize = 0;

            try (InputStream in = Files.newInputStream(sourcePath);
                 OutputStream out = Files.newOutputStream(Paths.get(encryptedFilePath))) {

                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    originalSize += bytesRead;
                    byte[] data = (bytesRead == CHUNK_SIZE) ? buffer : java.util.Arrays.copyOf(buffer, bytesRead);
                    byte[] encryptedChunk = sm4.encrypt(data);
                    encryptedSize += encryptedChunk.length;
                    out.write(encryptedChunk);
                }
            }

            String fileHash = sm3Util.hashFile(encryptedFilePath);

            EncryptedFileInfo info = new EncryptedFileInfo();
            info.setOriginalFileName(fileName);
            info.setEncryptedFilePath(encryptedFilePath);
            info.setMetaFilePath(metaFilePath);
            info.setIv(ivBase64);
            info.setFileHash(fileHash);
            info.setOriginalSize(originalSize);
            info.setEncryptedSize(encryptedSize);
            info.setKeyId(extractKeyId(keyBase64));

            saveMetaData(metaFilePath, info);

            log.info("文件加密成功: {}, 原大小: {} bytes, 加密大小: {} bytes", fileName, originalSize, encryptedSize);
            return info;

        } catch (IOException e) {
            log.error("文件加密IO异常", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, "文件加密失败: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("文件加密异常", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, "文件加密失败: " + e.getMessage(), e);
        }
    }

    public String decryptFile(String encryptedFilePath, String keyBase64, String outputDir) {
        if (encryptedFilePath == null || encryptedFilePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "加密文件路径不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }

        Path encryptedPath = Paths.get(encryptedFilePath);
        if (!Files.exists(encryptedPath)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "加密文件不存在: " + encryptedFilePath);
        }

        try {
            String metaPath = encryptedFilePath.replace(ENCRYPTED_EXT, META_EXT);
            EncryptedFileInfo meta = loadMetaData(metaPath);
            if (meta == null) {
                throw new CryptoException(CryptoException.FILE_CORRUPTED, "元数据文件缺失或损坏");
            }

            byte[] ivBytes = Base64.decode(meta.getIv());
            byte[] keyBytes = Base64.decode(keyBase64);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, keySpec, ivSpec);

            String outputFilePath = outputDir + File.separator + meta.getOriginalFileName();
            File outputFile = new File(outputFilePath);
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }

            try (InputStream in = Files.newInputStream(encryptedPath);
                 OutputStream out = Files.newOutputStream(outputFile.toPath())) {

                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    byte[] chunk = (bytesRead == CHUNK_SIZE) ? buffer : java.util.Arrays.copyOf(buffer, bytesRead);
                    byte[] decryptedChunk = sm4.decrypt(chunk);
                    out.write(decryptedChunk);
                }
            }

            log.info("文件解密成功: {}", outputFilePath);
            return outputFilePath;

        } catch (IOException e) {
            log.error("文件解密IO异常", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED, "文件解密失败: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("文件解密异常", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED, "文件解密失败: " + e.getMessage(), e);
        }
    }

    private void saveMetaData(String metaFilePath, EncryptedFileInfo info) {
        try {
            String json = JSONUtil.toJsonStr(info);
            FileUtil.writeUtf8String(json, metaFilePath);
        } catch (Exception e) {
            log.error("保存元数据失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, "元数据保存失败", e);
        }
    }

    private EncryptedFileInfo loadMetaData(String metaFilePath) {
        try {
            String json = FileUtil.readUtf8String(metaFilePath);
            return JSONUtil.toBean(json, EncryptedFileInfo.class);
        } catch (Exception e) {
            log.error("加载元数据失败", e);
            return null;
        }
    }

    private String extractKeyId(String keyBase64) {
        return keyBase64.length() > 8 ? keyBase64.substring(0, 8) : "default";
    }
}