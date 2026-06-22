package com.secretbox.user.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.util.Date;

@Data
@TableName("user")
public class User {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String username;
    private String password;
    private String realName;
    private String email;
    private String phone;
    private String roleCode;
    private String department;
    private Integer status;           // 1启用 0禁用
    private Date lockedUntil;         // 改为 Date
    private Integer loginFailCount;
    private Date lastLoginTime;       // 改为 Date
    private String createdBy;
    @TableField(fill = FieldFill.INSERT)
    private Date createdTime;         // 改为 Date
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updatedTime;         // 改为 Date
}