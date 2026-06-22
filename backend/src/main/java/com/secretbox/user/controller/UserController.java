package com.secretbox.user.controller;

import com.secretbox.common.result.Result;
import com.secretbox.user.dto.UserCreateDTO;
import com.secretbox.user.dto.UserRoleAssignDTO;
import com.secretbox.user.dto.UserUpdateDTO;
import com.secretbox.user.entity.User;
import com.secretbox.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserService userService;

    // 只有超级管理员可管理用户
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PostMapping("/create")
    public Result<User> createUser(@RequestBody @Valid UserCreateDTO dto) {
        return Result.success(userService.createUser(dto));
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PutMapping("/update")
    public Result<Void> updateUser(@RequestBody @Valid UserUpdateDTO dto) {
        userService.updateUser(dto);
        return Result.success();
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping("/delete/{userId}")
    public Result<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return Result.success();
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PutMapping("/assign-role")
    public Result<Void> assignRole(@RequestBody @Valid UserRoleAssignDTO dto) {
        userService.assignRole(dto);
        return Result.success();
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PutMapping("/revoke/{userId}")
    public Result<Void> revokeUser(@PathVariable Long userId) {
        userService.revokeUserPermissions(userId);
        return Result.success();
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/list")
    public Result<List<User>> listUsers(@RequestParam(required = false) String keyword) {
        return Result.success(userService.listUsers(keyword));
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/{userId}")
    public Result<User> getUser(@PathVariable Long userId) {
        return Result.success(userService.getUserById(userId));
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PutMapping("/reset-password")
    public Result<Void> resetPassword(@RequestParam Long userId, @RequestParam String newPassword) {
        userService.resetPassword(userId, newPassword);
        return Result.success();
    }

    // 测试接口：当前用户信息（任何登录用户可访问）
    @GetMapping("/me")
    public Result<User> getCurrentUser(@RequestParam String username) {
        // 实际应通过SecurityContext获取，简化演示
        // 这里仅作示例，真实场景需从SecurityContext获取
        return Result.success(userService.listUsers(username).stream().findFirst().orElse(null));
    }
}