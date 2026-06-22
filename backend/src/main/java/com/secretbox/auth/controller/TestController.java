package com.secretbox.auth.controller;

import com.secretbox.common.result.Result;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Result<String> adminTest() {
        return Result.success("超级管理员权限测试通过");
    }

    @GetMapping("/secretary")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'DEPT_SECRETARY')")
    public Result<String> secretaryTest() {
        return Result.success("保密员权限测试通过");
    }

    @GetMapping("/employee")
    @PreAuthorize("hasRole('EMPLOYEE')")
    public Result<String> employeeTest() {
        return Result.success("普通员工权限测试通过");
    }

    @GetMapping("/public")
    public Result<String> publicTest() {
        return Result.success("公开接口，无需认证");
    }
}