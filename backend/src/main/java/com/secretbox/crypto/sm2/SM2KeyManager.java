package com.secretbox.crypto.sm2;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.FileUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.secretbox.crypto.config.CryptoConfig;
import com.secretbox.crypto.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.charset.StandardCharsets;

/**
 * SM2密钥管理器
 * 功能：
 * 1. 生成SM2公私钥对
 * 2. 密钥存储与加载（本地文件存储）
 * 3. 密钥加密与签名（用户密钥加密）
 * 
 * SM2适用于：用户密钥加密、数字签名、身份认证
 */
@Slf4j
@Component
public class SM2KeyManager {
    
    @Autowired
    private CryptoConfig cryptoConfig;
    
    private static final String PUBLIC_KEY_SUFFIX = "_public.key";
    private static final String PRIVATE_KEY_SUFFIX = "_private.key";
    private static final String KEY_FILE_ENCODING = "UTF-8";
    
    /**
     * 生成SM2密钥对
     * 
     * @param keyId 密钥ID（用于标识）
     * @return SM2密钥对
     */
    public SM2KeyPair generateKeyPair(String keyId) {
        try {
            // 使用Hutool生成SM2密钥对
            SM2 sm2 = SmUtil.sm2();
            String privateKeyBase64 = Base64.encode(sm2.getPrivateKeyBytes());
            String publicKeyBase64 = Base64.encode(sm2.getPublicKeyBytes());
            
            SM2KeyPair keyPair = new SM2KeyPair(privateKeyBase64, publicKeyBase64);
            keyPair.setKeyId(keyId);
            keyPair.setCreateTime(System.currentTimeMillis());
            keyPair.setIsMaster(false);
            
            log.info("SM2密钥对生成成功, keyId: {}", keyId);
            return keyPair;
        } catch (Exception e) {
            log.error("SM2密钥对生成失败", e);
            throw new CryptoException(CryptoException.KEY_GEN_FAILED, 
                "SM2密钥对生成失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 生成系统主密钥对
     * 
     * @return SM2密钥对
     */
    public SM2KeyPair generateMasterKeyPair() {
        SM2KeyPair keyPair = generateKeyPair("MASTER");
        keyPair.setIsMaster(true);
        // 保存主密钥到默认路径
        saveKeyPair(keyPair, cryptoConfig.getKeyStorePath());
        return keyPair;
    }
    
    /**
     * 保存密钥对到文件
     * 
     * @param keyPair 密钥对
     * @param storePath 存储路径
     */
    public void saveKeyPair(SM2KeyPair keyPair, String storePath) {
        if (keyPair == null) {
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密钥对不能为空");
        }
        
        try {
            // 确保存储目录存在
            File storeDir = new File(storePath);
            if (!storeDir.exists()) {
                storeDir.mkdirs();
            }
            
            String keyId = keyPair.getKeyId() != null ? keyPair.getKeyId() : "default";
            String baseName = keyId + "_" + keyPair.getCreateTime();
            
            // 保存公钥
            String publicKeyPath = storePath + File.separator + baseName + PUBLIC_KEY_SUFFIX;
            FileUtil.writeString(keyPair.getPublicKey(), publicKeyPath, KEY_FILE_ENCODING);
            
            // 保存私钥
            String privateKeyPath = storePath + File.separator + baseName + PRIVATE_KEY_SUFFIX;
            FileUtil.writeString(keyPair.getPrivateKey(), privateKeyPath, KEY_FILE_ENCODING);
            
            log.info("SM2密钥对保存成功: {}", storePath);
        } catch (Exception e) {
            log.error("SM2密钥对保存失败", e);
            throw new CryptoException(CryptoException.KEY_GEN_FAILED, 
                "密钥保存失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 从文件加载密钥对
     * 
     * @param publicKeyPath 公钥文件路径
     * @param privateKeyPath 私钥文件路径
     * @return SM2密钥对
     */
    public SM2KeyPair loadKeyPair(String publicKeyPath, String privateKeyPath) {
        try {
            String publicKey = FileUtil.readString(publicKeyPath, KEY_FILE_ENCODING);
            String privateKey = FileUtil.readString(privateKeyPath, KEY_FILE_ENCODING);
            
            if (publicKey == null || publicKey.isEmpty()) {
                throw new CryptoException(CryptoException.KEY_INVALID, 
                    "公钥文件读取失败");
            }
            if (privateKey == null || privateKey.isEmpty()) {
                throw new CryptoException(CryptoException.KEY_INVALID, 
                    "私钥文件读取失败");
            }
            
            return new SM2KeyPair(privateKey, publicKey);
        } catch (Exception e) {
            log.error("SM2密钥对加载失败", e);
            throw new CryptoException(CryptoException.KEY_INVALID, 
                "密钥加载失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 使用SM2公钥加密数据
     * 
     * @param data 原始数据
     * @param publicKeyBase64 公钥（Base64编码）
     * @return 加密后的密文（Base64编码）
     */
    public String encryptWithPublicKey(String data, String publicKeyBase64) {
        try {
            SM2 sm2 = SmUtil.sm2(null, Base64.decode(publicKeyBase64));
            byte[] encrypted = sm2.encrypt(data.getBytes(StandardCharsets.UTF_8), KeyType.PublicKey);
            return Base64.encode(encrypted);
        } catch (Exception e) {
            log.error("SM2公钥加密失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "SM2加密失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 使用SM2私钥解密数据
     * 
     * @param encryptedBase64 密文（Base64编码）
     * @param privateKeyBase64 私钥（Base64编码）
     * @return 解密后的明文
     */
    public String decryptWithPrivateKey(String encryptedBase64, String privateKeyBase64) {
        try {
            SM2 sm2 = SmUtil.sm2(Base64.decode(privateKeyBase64), null);
            byte[] decrypted = sm2.decrypt(Base64.decode(encryptedBase64), KeyType.PrivateKey);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("SM2私钥解密失败", e);
            throw new CryptoException(CryptoException.DECRYPT_FAILED, 
                "SM2解密失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 使用SM2私钥签名
     * 
     * @param data 待签名的数据
     * @param privateKeyBase64 私钥（Base64编码）
     * @return 签名（Base64编码）
     */
    public String sign(String data, String privateKeyBase64) {
        try {
            SM2 sm2 = SmUtil.sm2(Base64.decode(privateKeyBase64), null);
            byte[] signature = sm2.sign(data.getBytes(StandardCharsets.UTF_8));
            return Base64.encode(signature);
        } catch (Exception e) {
            log.error("SM2签名失败", e);
            throw new CryptoException(CryptoException.ENCRYPT_FAILED, 
                "SM2签名失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 使用SM2公钥验签
     * 
     * @param data 原始数据
     * @param signatureBase64 签名（Base64编码）
     * @param publicKeyBase64 公钥（Base64编码）
     * @return true=验证通过
     */
    public boolean verify(String data, String signatureBase64, String publicKeyBase64) {
        try {
            SM2 sm2 = SmUtil.sm2(null, Base64.decode(publicKeyBase64));
            return sm2.verify(data.getBytes(StandardCharsets.UTF_8), 
                Base64.decode(signatureBase64));
        } catch (Exception e) {
            log.error("SM2验签失败", e);
            return false;
        }
    }
}