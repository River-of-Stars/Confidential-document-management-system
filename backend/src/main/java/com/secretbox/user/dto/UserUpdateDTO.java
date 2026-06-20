package com.secretbox.user.dto;

import lombok.Data;

@Data
public class UserUpdateDTO {
    private Long id;
    private String realName;
    private String email;
    private String phone;
    private String department;
    private Integer status; // 1启用 0禁用
}