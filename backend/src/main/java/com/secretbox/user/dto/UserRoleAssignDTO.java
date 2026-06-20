package com.secretbox.user.dto;

import lombok.Data;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.NotBlank;

@Data
public class UserRoleAssignDTO {
    @NotNull
    private Long userId;
    @NotBlank
    private String roleCode;
}