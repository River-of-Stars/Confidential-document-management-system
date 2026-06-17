package com.secretbox.crypto.sm3;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * SM3 哈希工具类
 * 功能：
 * 1. 字符串SM3哈希计算（用于日志链式校验）
 * 2. 文件SM3哈希计算（用于文件完整性校验）
 * 3. 支持大文件分块哈希计算（防内存溢出）
 * 
 * SM3摘要长度为256位（32字节），十六进制表示为64位字符串
 */
@Slf4j
@Component
public class SM3Util {
    
    // 分块大小：8MB，平衡内存与性能
    private static final int BUFFER_SIZE = 8 * 1024 * 1024;
    
    /**
     * 计算字符串的SM3哈希值
     * 
     * @param input 输入字符串
     * @return 64位十六进制哈希字符串
     * @throws CryptoException 输入为空时抛出
     */
    public String hashString(String input) {
        if (input == null || input.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "SM3哈希输入不能为空");
        }
        try {
            // 使用Hutool的SM3工具
            return SmUtil.sm3(input);
        } catch (Exception e) {
            log.error("SM3字符串哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, 
                "SM3哈希计算失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 计算字符串的SM3哈希值（使用字节数组）
     * 
     * @param bytes 输入字节数组
     * @return 64位十六进制哈希字符串
     */
    public String hashBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "SM3哈希输入字节数组不能为空");
        }
        try {
            return SmUtil.sm3(bytes);
        } catch (Exception e) {
            log.error("SM3字节数组哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, 
                "SM3哈希计算失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 计算文件的SM3哈希值（分块读取，支持大文件）
     * 
     * @param filePath 文件路径
     * @return 64位十六进制哈希字符串
     * @throws CryptoException 文件不存在、损坏或读取失败时抛出
     */
    public String hashFile(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "文件路径不能为空");
        }
        
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new CryptoException(CryptoException.FILE_CORRUPTED, 
                "文件不存在: " + filePath);
        }
        
        try (InputStream inputStream = Files.newInputStream(path)) {
            return hashInputStream(inputStream);
        } catch (IOException e) {
            log.error("文件SM3哈希计算失败: {}", filePath, e);
            throw new CryptoException(CryptoException.FILE_CORRUPTED, 
                "文件读取失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 计算输入流的SM3哈希值（分块读取）
     * 
     * @param inputStream 输入流
     * @return 64位十六进制哈希字符串
     */
    public String hashInputStream(InputStream inputStream) {
        if (inputStream == null) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "输入流不能为空");
        }
        
        try {
            // 使用Hutool的DigestUtil，支持分块读取
            byte[] hash = DigestUtil.digest("SM3", inputStream);
            return cn.hutool.core.util.HexUtil.encodeHexStr(hash);
        } catch (Exception e) {
            log.error("输入流SM3哈希计算失败", e);
            throw new CryptoException(CryptoException.HASH_MISMATCH, 
                "哈希计算失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 验证字符串与哈希值是否匹配
     * 
     * @param input 原始字符串
     * @param expectedHash 期望的哈希值（64位十六进制）
     * @return true=匹配，false=不匹配
     */
    public boolean verifyString(String input, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            return false;
        }
        String actualHash = hashString(input);
        return actualHash.equalsIgnoreCase(expectedHash);
    }
    
    /**
     * 验证文件与哈希值是否匹配（完整性校验）
     * 
     * @param filePath 文件路径
     * @param expectedHash 期望的哈希值（64位十六进制）
     * @return true=完整，false=损坏
     */
    public boolean verifyFile(String filePath, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            return false;
        }
        try {
            String actualHash = hashFile(filePath);
            return actualHash.equalsIgnoreCase(expectedHash);
        } catch (CryptoException e) {
            log.warn("文件完整性校验异常: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 生成日志链式校验哈希（用于审计日志防篡改）
     * 计算规则：SM3(上一条日志哈希 + 当前日志内容)
     * 
     * @param previousHash 上一条日志的哈希值
     * @param currentContent 当前日志内容
     * @return 当前日志的链式哈希值
     */
    public String chainHash(String previousHash, String currentContent) {
        if (currentContent == null || currentContent.isEmpty()) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "日志内容不能为空");
        }
        
        String combined;
        if (previousHash == null || previousHash.isEmpty()) {
            // 第一条日志，仅对内容哈希
            combined = currentContent;
        } else {
            // 拼接上一条哈希 + 当前内容
            combined = previousHash + currentContent;
        }
        
        return hashString(combined);
    }
}