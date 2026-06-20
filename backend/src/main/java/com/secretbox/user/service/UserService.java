package com.secretbox.user.service;

import com.secretbox.user.entity.User;
import com.secretbox.user.dto.UserCreateDTO;
import com.secretbox.user.dto.UserUpdateDTO;
import com.secretbox.user.dto.UserRoleAssignDTO;

import java.util.List;

public interface UserService {
    User createUser(UserCreateDTO dto);
    void updateUser(UserUpdateDTO dto);
    void deleteUser(Long userId);
    void assignRole(UserRoleAssignDTO dto);
    void revokeUserPermissions(Long userId);  // 离职回收权限（实际是禁用+移除角色）
    User getUserById(Long userId);
    List<User> listUsers(String keyword);
    void resetPassword(Long userId, String newPassword);