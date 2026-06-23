package com.secretbox.file.model;

import lombok.Data;
import java.util.Date;

@Data
public class FileUploadResponse {
    private Long fileId;
    private String fileName;
    private Date uploadTime;
}