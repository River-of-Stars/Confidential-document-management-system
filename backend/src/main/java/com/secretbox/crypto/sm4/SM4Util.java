package com.secretbox.crypto.sm4;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Slf4j
@Component
public class SM4Util {

    private static final int IV_LENGTH = 16;

    public String generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return Base64.encode(key);
    }

    public String generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return Base64.encode(iv);
    }

    public String encrypt(String plainText, String keyBase64) {
        if (plainText == null || plainText.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "明文不能为空");
        }
        byte[] key = Base64.decode(keyBase64);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        SymmetricCrypto sm4 = SmUtil.sm4(key, iv);  // ✅ 正确构造
        byte[] encrypted = sm4.encrypt(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.encode(iv) + ":" + Base64.encode(encrypted);
    }

    public String decrypt(String encryptedData, String keyBase64) {
        String[] parts = encryptedData.split(":");
        if (parts.length != 2) {
            throw new CryptoException(CryptoException.DECRYPT_FAILED, "密文格式错误");
        }
        byte[] iv = Base64.decode(parts[0]);
        byte[] cipher = Base64.decode(parts[1]);
        byte[] key = Base64.decode(keyBase64);
        SymmetricCrypto sm4 = SmUtil.sm4(key, iv);
        byte[] decrypted = sm4.decrypt(cipher);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public String encryptBytes(byte[] plainBytes, String keyBase64, String ivBase64) {
        byte[] key = Base64.decode(keyBase64);
        byte[] iv = (ivBase64 != null && !ivBase64.isEmpty()) ? Base64.decode(ivBase64) : new byte[IV_LENGTH];
        if (ivBase64 == null || ivBase64.isEmpty()) new SecureRandom().nextBytes(iv);
        SymmetricCrypto sm4 = SmUtil.sm4(key, iv);
        byte[] encrypted = sm4.encrypt(plainBytes);
        return Base64.encode(iv) + ":" + Base64.encode(encrypted);
    }

    public byte[] decryptBytes(String encryptedData, String keyBase64) {
        String[] parts = encryptedData.split(":");
        if (parts.length != 2) {
            throw new CryptoException(CryptoException.DECRYPT_FAILED, "密文格式错误");
        }
        byte[] iv = Base64.decode(parts[0]);
        byte[] cipher = Base64.decode(parts[1]);
        byte[] key = Base64.decode(keyBase64);
        SymmetricCrypto sm4 = SmUtil.sm4(key, iv);
        return sm4.decrypt(cipher);
    }
}