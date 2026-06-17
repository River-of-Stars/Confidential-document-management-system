package com.secretbox.crypto.sm2;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SM2密钥对实体
 * SM2为非对称加密算法，密钥长度为256位
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SM2KeyPair {
    
    /**
     * 私钥（Base64编码）
     */
    private String privateKey;
    
    /**
     * 公钥（Base64编码）
     */
    private String publicKey;
    
    /**
     * 密钥ID（用于标识用户或设备）
     */
    private String keyId;
    
    /**
     * 创建时间戳
     */
    private Long createTime;
    
    /**
     * 是否为主密钥（系统级）
     */
    private Boolean isMaster;
    
    public SM2KeyPair(String privateKey, String publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.createTime = System.currentTimeMillis();
        this.isMaster = false;
    }
}