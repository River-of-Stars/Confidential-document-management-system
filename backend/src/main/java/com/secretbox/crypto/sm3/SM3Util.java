package com.secretbox.crypto.sm3;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * SM3 哈希工具类
 * 使用 Hutool 5.8.x 的 API：
 * - 字符串/字节数组：DigestUtil.sm3(...) 返回 byte[]
 * - 输入流/文件：DigestUtil.digest("SM3", inputStream) 返回 byte[]
 */
@Slf4j
@Component
public class SM3Util {

    /**
     * 计算字符串的 SM3 哈希（十六进制小写）
     */
    public String hashString(String input) {
        if (input == null || input.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "SM3哈希输入不能为空");
        }
        try {
            byte[] hash = DigestUtil.sm3(input);
            return HexUtil.encodeHexStr(hash);
        } catch (Exception e) {
            log.error("SM3字符串哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "SM3哈希计算失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算字节数组的 SM3 哈希
     */
    public String hashBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, "SM3哈希输入字节数组不能为空");
        }
        try {
            byte[] hash = DigestUtil.sm3(bytes);
            return HexUtil.encodeHexStr(hash);
        } catch (Exception e) {
            log.error("SM3字节数组哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "SM3哈希计算失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算文件的 SM3 哈希（自动分块读取，适合大文件）
     */
    public String hashFile(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "文件路径不能为空");
        }
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "文件不存在: " + filePath);
        }
        try (InputStream inputStream = Files.newInputStream(path)) {
            return hashInputStream(inputStream);
        } catch (Exception e) {
            log.error("文件SM3哈希计算失败: {}", filePath, e);
            throw new CryptoException(CryptoException.FILE_CORRUPTED, "文件读取失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算输入流的 SM3 哈希
     * 使用 DigestUtil.digest("SM3", inputStream) 替代不存在的 sm3(InputStream)
     */
    public String hashInputStream(InputStream inputStream) {
        if (inputStream == null) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入流不能为空");
        }
        try {
            // 关键修正：使用 digest 方法指定算法
            byte[] hash = DigestUtil.digest("SM3", inputStream);
            return HexUtil.encodeHexStr(hash);
        } catch (Exception e) {
            log.error("输入流SM3哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "哈希计算失败: " + e.getMessage(), e);
        }
    }

    /**
     * 验证字符串与哈希是否匹配
     */
    public boolean verifyString(String input, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            return false;
        }
        try {
            String actualHash = hashString(input);
            return actualHash.equalsIgnoreCase(expectedHash);
        } catch (Exception e) {
            log.warn("字符串验证异常", e);
            return false;
        }
    }

    /**
     * 验证文件完整性
     */
    public boolean verifyFile(String filePath, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            return false;
        }
        try {
            String actualHash = hashFile(filePath);
            return actualHash.equalsIgnoreCase(expectedHash);
        } catch (Exception e) {
            log.warn("文件完整性校验异常: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 链式哈希（日志防篡改）
     * 规则：SM3(前一条哈希 + 当前内容)
     */
    public String chainHash(String previousHash, String currentContent) {
        if (currentContent == null || currentContent.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, "日志内容不能为空");
        }
        String combined = (previousHash == null || previousHash.isEmpty()) 
                          ? currentContent 
                          : previousHash + currentContent;
        return hashString(combined);
    }

    /**
     * 直接返回 SM3 哈希字节数组（供底层使用）
     */
    public byte[] hashToBytes(byte[] input) {
        if (input == null || input.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, "输入不能为空");
        }
        try {
            return DigestUtil.sm3(input);
        } catch (Exception e) {
            log.error("SM3哈希(字节)计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, "哈希计算失败", e);
        }
    }
}