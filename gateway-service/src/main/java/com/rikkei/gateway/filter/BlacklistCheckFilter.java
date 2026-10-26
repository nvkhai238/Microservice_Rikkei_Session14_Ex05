package com.rikkei.gateway.filter;

import com.rikkei.gateway.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class BlacklistCheckFilter implements GlobalFilter, Ordered {
    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/auth/login", "/api/auth/register", "/api/auth/refresh"
    );

    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtProperties jwtProperties;

    public BlacklistCheckFilter(ReactiveStringRedisTemplate redisTemplate, JwtProperties jwtProperties) {
        this.redisTemplate = redisTemplate;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Bo qua kiem tra blacklist cho public auth endpoints
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        // 1. Trich xuat Token tu Header Authorization
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);
        String jti;
        try {
            // 2. Parse JWT de lay jti
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            jti = claims.getId();
        } catch (JwtException e) {
            return chain.filter(exchange);
        }

        if (jti == null) {
            return chain.filter(exchange);
        }

        // 3. Truy van Redis bang ReactiveStringRedisTemplate (Non-blocking)
        return redisTemplate.hasKey(BLACKLIST_PREFIX + jti)
                .flatMap(isBlacklisted -> {
                    // 4. Neu ton tai trong Redis (da bi blacklist / logout): Tra ve 401 Unauthorized ngay lap tuc
                    if (Boolean.TRUE.equals(isBlacklisted)) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    // 5. Neu hop le: tiep tuc chuoi loc
                    return chain.filter(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -1; // Highest priority
    }
}
