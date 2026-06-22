package com.secretbox.auth.controller;

import com.secretbox.auth.model.LoginRequest;
import com.secretbox.auth.model.LoginResponse;
import com.secretbox.auth.service.JwtService;
import com.secretbox.auth.service.LoginAttemptService;
import com.secretbox.common.exception.BusinessException;
import com.secretbox.common.result.Result;
import com.secretbox.user.entity.User;
import com.secretbox.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDateTime;
import java.util.Date;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;
    private final UserMapper userMapper;

    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        String username = request.getUsername();

        // 检查是否被锁定
        if (loginAttemptService.isBlocked(username)) {
            throw new BusinessException(401, "账号已锁定，请30分钟后重试");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, request.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 登录成功，清除失败记录
            loginAttemptService.loginSucceeded(username);

            // 生成JWT
            User user = userMapper.selectOne(
                new com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper<User>()
                    .eq(User::getUsername, username)
            );
            String token = jwtService.generateToken(username, user.getRoleCode());

            // 更新最后登录时间
            user.setLastLoginTime(new Date());
            userMapper.updateById(user);

            return Result.success(new LoginResponse(token, user.getRoleCode(), user.getRealName()));

        } catch (BadCredentialsException e) {
            loginAttemptService.loginFailed(username);
            int remaining = loginAttemptService.getRemainingAttempts(username);
            String msg = "用户名或密码错误，剩余尝试次数: " + remaining;
            if (remaining == 0) {
                msg = "密码错误次数过多，账号已锁定30分钟";
            }
            throw new BusinessException(401, msg);
        }
    }

    @PostMapping("/logout")
    public Result<Void> logout() {
        // JWT无状态，仅清除客户端token即可，服务端无需操作
        return Result.success();
    }
}