package com.secretbox.crypto.exception;

/**
国密加密自定义异常
用于统一捕获加密/解密/哈希过程中的各类异常
*/
public class CryptoException extends RuntimeException {
    
    private static final long serialVersionUID = 1L;
    
    private String errorCode;
    
    public CryptoException(String message) {
        super(message);
    }
    
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public CryptoException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public CryptoException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
    
    // 预定义错误码
    public static final String KEY_INVALID = "CRYPTO_001";
    public static final String FILE_CORRUPTED = "CRYPTO_002";
    public static final String DECRYPT_FAILED = "CRYPTO_003";
    public static final String ENCRYPT_FAILED = "CRYPTO_004";
    public static final String HASH_MISMATCH = "CRYPTO_005";
    public static final String KEY_GEN_FAILED = "CRYPTO_006";
}