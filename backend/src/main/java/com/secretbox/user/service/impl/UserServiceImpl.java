package com.secretbox.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.secretbox.common.exception.BusinessException;
import com.secretbox.role.enums.RoleEnum;
import com.secretbox.user.dto.UserCreateDTO;
import com.secretbox.user.dto.UserRoleAssignDTO;
import com.secretbox.user.dto.UserUpdateDTO;
import com.secretbox.user.entity.User;
import com.secretbox.user.mapper.UserMapper;
import com.secretbox.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public User createUser(UserCreateDTO dto) {
        // 检查用户名唯一
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUsername, dto.getUsername());
        if (userMapper.selectOne(wrapper) != null) {
            throw new BusinessException("用户名已存在");
        }
        // 校验角色
        if (RoleEnum.fromCode(dto.getRoleCode()) == null) {
            throw new BusinessException("无效角色编码");
        }
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setRealName(dto.getRealName());
        user.setEmail(dto.getEmail());
        user.setPhone(dto.getPhone());
        user.setRoleCode(dto.getRoleCode());
        user.setDepartment(dto.getDepartment());
        user.setStatus(1);
        user.setLoginFailCount(0);
        userMapper.insert(user);
        return user;
    }

    @Override
    @Transactional
    public void updateUser(UserUpdateDTO dto) {
        User user = userMapper.selectById(dto.getId());
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        // 只允许更新部分字段
        if (dto.getRealName() != null) user.setRealName(dto.getRealName());
        if (dto.getEmail() != null) user.setEmail(dto.getEmail());
        if (dto.getPhone() != null) user.setPhone(dto.getPhone());
        if (dto.getDepartment() != null) user.setDepartment(dto.getDepartment());
        if (dto.getStatus() != null) user.setStatus(dto.getStatus());
        userMapper.updateById(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long userId) {
        // 物理删除（或逻辑删除，这里简单物理删除）
        int rows = userMapper.deleteById(userId);
        if (rows == 0) {
            throw new BusinessException("用户不存在");
        }
    }

    @Override
    @Transactional
    public void assignRole(UserRoleAssignDTO dto) {
        User user = userMapper.selectById(dto.getUserId());
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        if (RoleEnum.fromCode(dto.getRoleCode()) == null) {
            throw new BusinessException("无效角色编码");
        }
        user.setRoleCode(dto.getRoleCode());
        userMapper.updateById(user);
    }

    @Override
    @Transactional
    public void revokeUserPermissions(Long userId) {
        // 离职回收：禁用账号，清除角色（可选）
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        user.setStatus(0);
        // 可选：移除角色，但不能为空，可以设置默认角色 EMPLOYEE
        user.setRoleCode(RoleEnum.EMPLOYEE.getCode());
        userMapper.updateById(user);
    }

    @Override
    public User getUserById(Long userId) {
        return userMapper.selectById(userId);
    }

    @Override
    public List<User> listUsers(String keyword) {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        if (keyword != null && !keyword.isEmpty()) {
            wrapper.like(User::getUsername, keyword)
                   .or()
                   .like(User::getRealName, keyword);
        }
        wrapper.orderByDesc(User::getCreatedTime);
        return userMapper.selectList(wrapper);
    }

    @Override
    @Transactional
    public void resetPassword(Long userId, String newPassword) {
        User user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updateById(user);
    }
}