package com.secretbox.auth.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.secretbox.auth.model.SecretBoxUserDetails;
import com.secretbox.user.entity.User;
import com.secretbox.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUsername, username);
        User user = userMapper.selectOne(wrapper);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        if (user.getStatus() == 0) {
            throw new UsernameNotFoundException("账号已禁用");
        }
        return new SecretBoxUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getRoleCode(),
                user.getDepartment(),
                user.getRealName(),
                user.getStatus() == 1
        );
    }
}