package com.secretbox.crypto.sm4;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SM4 加密文件元数据信息
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptedFileInfo {
    private String originalFileName;   // 原始文件名
    private String encryptedFilePath;  // 加密后的文件路径
    private String metaFilePath;       // 元数据文件路径
    private String iv;                 // 加密使用的IV（Base64编码）
    private String fileHash;           // 加密后文件的SM3哈希值（用于完整性校验）
    private long originalSize;         // 原始文件大小（字节）
    private long encryptedSize;        // 加密后文件大小（字节）
    private String keyId;              // 用于解密的密钥ID（可标识用户/设备）
}