package com.secretbox.auth.model;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Getter
public class SecretBoxUserDetails implements UserDetails {
    private final Long userId;
    private final String username;
    private final String password;
    private final String roleCode;
    private final String department;
    private final String realName;
    private final boolean enabled;

    public SecretBoxUserDetails(Long userId, String username, String password, String roleCode,
                                String department, String realName, boolean enabled) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.roleCode = roleCode;
        this.department = department;
        this.realName = realName;
        this.enabled = enabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + roleCode));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}