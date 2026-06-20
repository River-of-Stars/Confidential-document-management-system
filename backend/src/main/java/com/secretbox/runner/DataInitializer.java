package com.secretbox.runner;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.secretbox.user.entity.User;
import com.secretbox.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // 检查是否存在超级管理员
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUsername, "admin");
        if (userMapper.selectOne(wrapper) == null) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRealName("系统管理员");
            admin.setRoleCode("SUPER_ADMIN");
            admin.setStatus(1);
            userMapper.insert(admin);
            log.info("✅ 默认超级管理员已创建: admin / admin123");
        }
    }
}