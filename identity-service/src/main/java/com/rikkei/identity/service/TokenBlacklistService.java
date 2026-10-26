package com.rikkei.identity.service;

import com.rikkei.identity.util.JwtUtils;
import io.jsonwebtoken.Claims;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {
    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;
    private final JwtUtils jwtUtils;

    public TokenBlacklistService(StringRedisTemplate redisTemplate, JwtUtils jwtUtils) {
        this.redisTemplate = redisTemplate;
        this.jwtUtils = jwtUtils;
    }

    public void blacklistToken(String token) {
        Claims claims = jwtUtils.getClaimsFromToken(token);
        String jti = claims.getId();
        Date expiration = claims.getExpiration();

        long ttlMillis = expiration.getTime() - Instant.now().toEpochMilli();
        if (ttlMillis > 0 && jti != null) {
            redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + jti,
                    "revoked",
                    ttlMillis,
                    TimeUnit.MILLISECONDS
            );
        }
    }

    public boolean isBlacklisted(String token) {
        try {
            String jti = jwtUtils.getJtiFromToken(token);
            if (jti == null) return false;
            return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti));
        } catch (Exception e) {
            return false;
        }
    }
}
