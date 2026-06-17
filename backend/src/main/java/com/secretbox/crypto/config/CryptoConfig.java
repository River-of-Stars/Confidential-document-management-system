package com.secretbox.crypto.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.security.Security;

/**
 * 国密加密配置类
 * 注册BouncyCastle安全提供者，加载密钥存储路径配置
 */
@Configuration
public class CryptoConfig {
    
    @Value("${crypto.key-store-path:./keys}")
    private String keyStorePath;
    
    @Value("${crypto.sm4.key-length:128}")
    private int sm4KeyLength;
    
    @Value("${crypto.sm4.work-mode:CBC}")
    private String sm4WorkMode;
    
    @Value("${crypto.sm4.padding:PKCS5Padding}")
    private String sm4Padding;
    
    @PostConstruct
    public void init() {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public String getKeyStorePath() {
        return keyStorePath;
    }
    
    public int getSm4KeyLength() {
        return sm4KeyLength;
    }
    
    public String getSm4Algorithm() {
        // 返回SM4算法全名，如：SM4/CBC/PKCS5Padding
        return "SM4/" + sm4WorkMode + "/" + sm4Padding;
    }
}