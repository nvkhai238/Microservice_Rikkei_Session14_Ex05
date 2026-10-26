package com.rikkei.identity.service;

import com.rikkei.identity.dto.LoginRequest;
import com.rikkei.identity.dto.RegisterRequest;
import com.rikkei.identity.dto.TokenResponseDTO;
import com.rikkei.identity.dto.UserResponse;
import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.entity.User;
import com.rikkei.identity.exception.DuplicateUsernameException;
import com.rikkei.identity.repository.UserRepository;
import com.rikkei.identity.util.JwtUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public AuthenticationService(UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 JwtUtils jwtUtils,
                                 RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Registers a new user with the given credentials.
     * Assigns the default role "USER".
     *
     * @param request registration details
     * @return the created user's info
     * @throws DuplicateUsernameException if the username is already taken
     */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new DuplicateUsernameException(request.username());
        }

        String encodedPassword = passwordEncoder.encode(request.password());
        User user = new User(
            UUID.randomUUID().toString(),
            request.username(),
            encodedPassword,
            "USER"
        );
        User saved = userRepository.save(user);
        return new UserResponse(saved.getId(), saved.getUsername(), saved.getRole());
    }

    /**
     * Authenticates a user and issues both an access token and a refresh token.
     *
     * @param request login credentials
     * @return JWT access token and refresh token
     * @throws IllegalArgumentException if credentials are invalid
     */
    @Transactional
    public TokenResponseDTO login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
            .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new TokenResponseDTO(accessToken, refreshToken.getToken());
    }
}
