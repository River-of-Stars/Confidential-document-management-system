package com.secretbox.file.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;
import java.util.Date;

@Data
@TableName("file_metadata")
public class FileMetadata {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String fileName;
    private Long fileSize;
    private String uploader;       // 上传人用户名
    private String uploaderName;   // 上传人姓名
    private Date uploadTime;
    private Integer classification; // 密级（对应枚举level）
    private String sm3Hash;        // 原文件SM3哈希
    private String minioObjectName; // MinIO中的对象名（UUID）
    private String encryptKey;     // 文件独立SM4密钥（Base64）
    private String contentType;
    @TableField(fill = FieldFill.INSERT)
    private Date createdTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updatedTime;
}