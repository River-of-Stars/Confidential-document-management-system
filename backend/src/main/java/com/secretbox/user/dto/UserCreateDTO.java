package com.secretbox.user.dto;

import lombok.Data;
import javax.validation.constraints.NotBlank;

@Data
public class UserCreateDTO {
    @NotBlank(message = "用户名不能为空")
    private String username;
    @NotBlank(message = "密码不能为空")
    private String password;
    private String realName;
    private String email;
    private String phone;
    @NotBlank(message = "角色不能为空")
    private String roleCode;
    private String department;
}