package com.secretbox.crypto.sm3;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
@Component
public class SM3Util {

    public String hashString(String input) {
        if (input == null || input.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入不能为空");
        }
        try {
            return SmUtil.sm3(input);
        } catch (Exception e) {
            log.error("SM3哈希失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "哈希计算失败", e);
        }
    }

    public String hashBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入不能为空");
        }
        try {
            // 将 byte[] 转换为输入流
            return SmUtil.sm3(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            log.error("SM3哈希失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "哈希计算失败", e);
        }
    }

    public String hashFile(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "文件路径不能为空");
        }
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "文件不存在");
        }
        try (InputStream in = Files.newInputStream(path)) {
            return hashInputStream(in);
        } catch (Exception e) {
            log.error("文件SM3哈希失败", e);
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "文件读取失败", e);
        }
    }

    public String hashInputStream(InputStream inputStream) {
        if (inputStream == null) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入流不能为空");
        }
        try {
            return SmUtil.sm3(inputStream);
        } catch (Exception e) {
            log.error("流SM3哈希失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "哈希计算失败", e);
        }
    }

    // 其他方法同上，调用 hashString 等
    public boolean verifyString(String input, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) return false;
        return expectedHash.equalsIgnoreCase(hashString(input));
    }

    public boolean verifyFile(String filePath, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) return false;
        return expectedHash.equalsIgnoreCase(hashFile(filePath));
    }

    public String chainHash(String previousHash, String currentContent) {
        if (currentContent == null || currentContent.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "日志内容不能为空");
        }
        String combined = (previousHash == null || previousHash.isEmpty()) ? currentContent : previousHash + currentContent;
        return hashString(combined);
    }

    public byte[] hashToBytes(byte[] input) {
        if (input == null || input.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入不能为空");
        }
        String hex = SmUtil.sm3(new ByteArrayInputStream(input));
        return HexUtil.decodeHex(hex);
    }
}