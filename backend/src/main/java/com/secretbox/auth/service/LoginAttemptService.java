package com.secretbox.auth.service;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    // 存储用户名 -> 失败次数
    private final ConcurrentHashMap<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    // 存储用户名 -> 锁定到期时间
    private final ConcurrentHashMap<String, LocalDateTime> lockCache = new ConcurrentHashMap<>();

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 30;

    public void loginSucceeded(String username) {
        attemptsCache.remove(username);
        lockCache.remove(username);
    }

    public void loginFailed(String username) {
        int attempts = attemptsCache.getOrDefault(username, 0) + 1;
        attemptsCache.put(username, attempts);
        if (attempts >= MAX_ATTEMPTS) {
            lockCache.put(username, LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
        }
    }

    public boolean isBlocked(String username) {
        LocalDateTime lockedUntil = lockCache.get(username);
        if (lockedUntil == null) {
            return false;
        }
        if (LocalDateTime.now().isAfter(lockedUntil)) {
            // 解锁
            lockCache.remove(username);
            attemptsCache.remove(username);
            return false;
        }
        return true;
    }

    public int getRemainingAttempts(String username) {
        if (isBlocked(username)) {
            return 0;
        }
        int attempts = attemptsCache.getOrDefault(username, 0);
        return Math.max(0, MAX_ATTEMPTS - attempts);
    }
}