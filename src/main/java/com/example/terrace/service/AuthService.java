
package com.example.terrace.service;

import com.example.terrace.dto.user.LoginRequest;
import com.example.terrace.dto.user.LoginResponse;
import com.example.terrace.mapper.UserMapper;
import com.example.terrace.model.User;
import com.example.terrace.repository.UserRepository;
import com.example.terrace.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    /**
     * Аутентификация пользователя
     */
    public LoginResponse login(LoginRequest loginRequest) {
        try {
            // Аутентификация через Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            // Получаем пользователя из БД
            User user = userRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Генерируем JWT токен
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtil.generateToken(userDetails);

            log.info("User logged in successfully: {}", user.getEmail());

            // Используем маппер для создания ответа
            return userMapper.toSuccessResponse(user, token);

        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for user: {}", loginRequest.getEmail());
            return userMapper.toErrorResponse("Invalid email or password");
        } catch (Exception e) {
            log.error("Login failed for user: {}", loginRequest.getEmail(), e);
            return userMapper.toErrorResponse("Login failed");
        }
    }

    /**
     * Проверка валидности токена
     */
    public boolean isTokenValid(String token) {
        try {
            return jwtUtil.isTokenValid(token);
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Извлечение информации о пользователе из токена
     */
    public LoginResponse.UserInfo getUserInfoFromToken(String token) {
        try {
            String email = jwtUtil.extractUsername(token);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return userMapper.toUserInfo(user);
        } catch (Exception e) {
            log.error("Failed to get user info from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Обновление токена (refresh)
     */
    public LoginResponse refreshToken(String oldToken) {
        try {
            if (!isTokenValid(oldToken)) {
                return userMapper.toErrorResponse("Invalid token");
            }

            String email = jwtUtil.extractUsername(oldToken);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Создаем новый токен
            String newToken = jwtUtil.refreshToken(oldToken);

            if (newToken != null) {
                return userMapper.toSuccessResponse(user, newToken);
            } else {
                return userMapper.toErrorResponse("Failed to refresh token");
            }

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            return userMapper.toErrorResponse("Token refresh failed");
        }
    }
}