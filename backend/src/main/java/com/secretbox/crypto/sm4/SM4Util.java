package com.secretbox.crypto.sm4;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.secretbox.crypto.config.CryptoConfig;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * SM4 核心工具类
 * SM4为对称加密算法，密钥长度128位
 * 
 * 功能：
 * 1. 生成SM4密钥
 * 2. 加密/解密字节数组
 * 3. 加密/解密字符串
 * 4. 支持CBC模式+随机IV
 * 
 * 注意：大文件加密请使用SM4FileProcessor（分片处理）
 */
@Slf4j
@Component
public class SM4Util {
    
    @Autowired
    private CryptoConfig cryptoConfig;
    
    private static final int IV_LENGTH = 16; // SM4块大小16字节
    
    /**
     * 生成随机SM4密钥（Base64编码）
     * 
     * @return Base64编码的密钥
     */
    public String generateKey() {
        try {
            byte[] keyBytes = new byte[16]; // SM4密钥128位 = 16字节
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(keyBytes);
            return Base64.encode(keyBytes);
        } catch (Exception e) {
            log.error("SM4密钥生成失败", e);
            throw new CryptoException(CryptoException.KEY_GEN_FAILED, 
                "SM4密钥生成失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 生成随机IV向量（Base64编码，用于CBC模式）
     * 
     * @return Base64编码的IV
     */
    public String generateIV() {
        byte[] ivBytes = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        return Base64.encode(ivBytes);
    }
    
    /**
     * SM4加密（CBC模式，自动生成随机IV）
     * 
     * @param plainText 明文
     * @param keyBase64 密钥（Base64编码）
     * @return 加密结果包含密文和IV（格式: IV_BASE64:CIPHER_BASE64）
     */
    public String encrypt(String plainText, String keyBase64) {
        if (plainText == null || plainText.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "明文不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密钥不能为空");
        }
        
        try {
            byte[] keyBytes = Base64.decode(keyBase64);
            // 生成随机IV
            byte[] ivBytes = new byte[IV_LENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(ivBytes);
            
            // 创建SM4加密器（CBC模式）
            SymmetricCrypto sm4 = SmUtil.sm4(keyBytes, ivBytes);
            byte[] encrypted = sm4.encrypt(plainText.getBytes(StandardCharsets.UTF_8));
            
            // 返回格式: IV_BASE64:CIPHER_BASE64
            return Base64.encode(ivBytes) + ":" + Base64.encode(encrypted);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "SM4加密失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * SM4解密（CBC模式，从加密结果中提取IV）
     * 
     * @param encryptedData 加密数据（格式: IV_BASE64:CIPHER_BASE64）
     * @param keyBase64 密钥（Base64编码）
     * @return 解密后的明文
     */
    public String decrypt(String encryptedData, String keyBase64) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密文不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密钥不能为空");
        }
        
        try {
            String[] parts = encryptedData.split(":");
            if (parts.length != 2) {
                throw new CryptoException(CryptoException.DECRYPT_FAILED, 
                    "密文格式错误，应为 IV:CIPHER");
            }
            
            byte[] ivBytes = Base64.decode(parts[0]);
            byte[] cipherBytes = Base64.decode(parts[1]);
            
            SymmetricCrypto sm4 = SmUtil.sm4(Base64.decode(keyBase64), ivBytes);
            byte[] decrypted = sm4.decrypt(cipherBytes);
            
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("SM4解密失败", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED, 
                "SM4解密失败，可能密钥错误或数据损坏: " + e.getMessage(), e);
        }
    }
    
    /**
     * SM4加密字节数组
     * 
     * @param plainBytes 明文字节数组
     * @param keyBase64 密钥（Base64编码）
     * @param ivBase64 IV向量（Base64编码，若为空则自动生成）
     * @return 加密结果（格式: IV_BASE64:CIPHER_BASE64）
     */
    public String encryptBytes(byte[] plainBytes, String keyBase64, String ivBase64) {
        if (plainBytes == null || plainBytes.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "明文数据不能为空");
        }
        
        try {
            byte[] keyBytes = Base64.decode(keyBase64);
            byte[] ivBytes;
            
            if (ivBase64 != null && !ivBase64.isEmpty()) {
                ivBytes = Base64.decode(ivBase64);
            } else {
                ivBytes = new byte[IV_LENGTH];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(ivBytes);
            }
            
            SymmetricCrypto sm4 = SmUtil.sm4(keyBytes, ivBytes);
            byte[] encrypted = sm4.encrypt(plainBytes);
            
            return Base64.encode(ivBytes) + ":" + Base64.encode(encrypted);
        } catch (Exception e) {
            log.error("SM4字节加密失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "SM4加密失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * SM4解密字节数组
     * 
     * @param encryptedData 加密数据（格式: IV_BASE64:CIPHER_BASE64）
     * @param keyBase64 密钥（Base64编码）
     * @return 解密后的字节数组
     */
    public byte[] decryptBytes(String encryptedData, String keyBase64) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密文不能为空");
        }
        
        try {
            String[] parts = encryptedData.split(":");
            if (parts.length != 2) {
                throw new CryptoException(CryptoException.DECRYPT_FAILED, 
                    "密文格式错误");
            }
            
            byte[] ivBytes = Base64.decode(parts[0]);
            byte[] cipherBytes = Base64.decode(parts[1]);
            
            SymmetricCrypto sm4 = SmUtil.sm4(Base64.decode(keyBase64), ivBytes);
            return sm4.decrypt(cipherBytes);
        } catch (Exception e) {
            log.error("SM4字节解密失败", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED, 
                "SM4解密失败: " + e.getMessage(), e);
        }
    }
}