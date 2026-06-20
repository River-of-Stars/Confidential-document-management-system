package com.secretbox.crypto.sm4;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * SM4 对称加密工具类
 * 修正说明：使用 Hutool 5.x 正确的构造方式
 */
@Slf4j
@Component
public class SM4Util {

    private static final int IV_LENGTH = 16; // SM4块大小16字节
    private static final String ALGORITHM = "SM4/CBC/PKCS5Padding";

    /**
     * 生成随机SM4密钥（Base64编码）
     */
    public String generateKey() {
        try {
            byte[] keyBytes = new byte[16];
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
     * 生成随机IV向量（Base64编码）
     */
    public String generateIV() {
        byte[] ivBytes = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(ivBytes);
        return Base64.encode(ivBytes);
    }

    /**
     * SM4加密（CBC模式，自动生成随机IV）
     * @param plainText 明文
     * @param keyBase64 密钥（Base64编码）
     * @return 加密结果格式：IV_BASE64:CIPHER_BASE64
     */
    public String encrypt(String plainText, String keyBase64) {
        if (plainText == null || plainText.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "明文不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }

        try {
            byte[] keyBytes = Base64.decode(keyBase64);
            byte[] ivBytes = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(ivBytes);

            // 使用正确的构造方法
            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, keyBytes, ivBytes);
            byte[] encrypted = sm4.encrypt(plainText.getBytes(StandardCharsets.UTF_8));

            return Base64.encode(ivBytes) + ":" + Base64.encode(encrypted);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED,
                    "SM4加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * SM4解密（CBC模式）
     * @param encryptedData 加密数据（格式：IV_BASE64:CIPHER_BASE64）
     * @param keyBase64 密钥（Base64编码）
     * @return 解密后的明文
     */
    public String decrypt(String encryptedData, String keyBase64) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密文不能为空");
        }
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密钥不能为空");
        }

        try {
            String[] parts = encryptedData.split(":");
            if (parts.length != 2) {
                throw new CryptoException(CryptoException.DECRYPT_FAILED, "密文格式错误");
            }

            byte[] ivBytes = Base64.decode(parts[0]);
            byte[] cipherBytes = Base64.decode(parts[1]);

            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, Base64.decode(keyBase64), ivBytes);
            byte[] decrypted = sm4.decrypt(cipherBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("SM4解密失败", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED,
                    "解密失败，可能密钥错误或数据损坏: " + e.getMessage(), e);
        }
    }

    /**
     * 加密字节数组（返回与字符串相同格式）
     */
    public String encryptBytes(byte[] plainBytes, String keyBase64, String ivBase64) {
        if (plainBytes == null || plainBytes.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, "明文数据不能为空");
        }

        try {
            byte[] keyBytes = Base64.decode(keyBase64);
            byte[] ivBytes;
            if (ivBase64 != null && !ivBase64.isEmpty()) {
                ivBytes = Base64.decode(ivBase64);
            } else {
                ivBytes = new byte[IV_LENGTH];
                new SecureRandom().nextBytes(ivBytes);
            }

            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, keyBytes, ivBytes);
            byte[] encrypted = sm4.encrypt(plainBytes);
            return Base64.encode(ivBytes) + ":" + Base64.encode(encrypted);
        } catch (Exception e) {
            log.error("SM4字节加密失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED,
                    "SM4加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 解密字节数组
     */
    public byte[] decryptBytes(String encryptedData, String keyBase64) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "密文不能为空");
        }

        try {
            String[] parts = encryptedData.split(":");
            if (parts.length != 2) {
                throw new CryptoException(CryptoException.DECRYPT_FAILED, "密文格式错误");
            }

            byte[] ivBytes = Base64.decode(parts[0]);
            byte[] cipherBytes = Base64.decode(parts[1]);

            SymmetricCrypto sm4 = new SymmetricCrypto(ALGORITHM, Base64.decode(keyBase64), ivBytes);
            return sm4.decrypt(cipherBytes);
        } catch (Exception e) {
            log.error("SM4字节解密失败", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED,
                    "解密失败: " + e.getMessage(), e);
        }
    }
}