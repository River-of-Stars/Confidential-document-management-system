package com.secretbox.auth.filter;

import com.secretbox.auth.model.SecretBoxUserDetails;
import com.secretbox.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 获取请求头中的 Authorization
        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            try {
                username = jwtService.extractUsername(jwt);
            } catch (Exception e) {
                log.warn("JWT解析失败: {}", e.getMessage());
            }
        }

        // 如果存在 username 且当前上下文未认证
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtService.validateToken(jwt, username)) {
                // 从 Token 中提取额外信息
                Claims claims = jwtService.extractAllClaims(jwt);
                Long userId = claims.get("userId", Long.class);
                String role = claims.get("role", String.class);
                String department = claims.get("department", String.class);

                // 构建自定义 UserDetails
                SecretBoxUserDetails userDetails = new SecretBoxUserDetails(
                        userId,
                        username,
                        "",  // 密码无需填充
                        role,
                        department,
                        "",  // realName 可从数据库查，但此处简化为空
                        true
                );

                // 创建认证 Token
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 设置到 SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.debug("用户认证成功: {}", username);
            }
        }

        filterChain.doFilter(request, response);
    }
}