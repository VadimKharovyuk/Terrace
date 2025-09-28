// ============================================================================
// 1. СЕРВИС РЕГИСТРАЦИИ (исправленный)
// ============================================================================

package com.example.terrace.service;

import com.example.terrace.dto.user.RegisterRequest;
import com.example.terrace.dto.user.LoginResponse;
import com.example.terrace.mapper.UserMapper;
import com.example.terrace.model.User;
import com.example.terrace.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegisterService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    /**
     * Регистрация нового пользователя
     */
    public LoginResponse register(RegisterRequest registerRequest) {
        try {
            // Проверяем совпадение паролей
            if (!registerRequest.getPassword().equals(registerRequest.getConfirmPassword())) {
                return userMapper.toErrorResponse("Passwords do not match");
            }

            // Проверяем существование пользователя
            if (userRepository.existsByEmail(registerRequest.getEmail())) {
                return userMapper.toErrorResponse("Email already exists");
            }

            // Шифруем пароль
            String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

            // Создаем пользователя через маппер
            User user = userMapper.toEntity(registerRequest, encodedPassword);

            // Сохраняем в БД
            User savedUser = userRepository.save(user);

            log.info("User registered successfully: {}", savedUser.getEmail());

            // Возвращаем успешный ответ без токена (требуем отдельный логин)
            return new LoginResponse(
                    "Registration successful. Please login.",
                    null, // Без токена - требуем отдельный логин
                    userMapper.toUserInfo(savedUser)
            );

        } catch (Exception e) {
            log.error("Registration failed for user: {}", registerRequest.getEmail(), e);
            return userMapper.toErrorResponse("Registration failed: " + e.getMessage());
        }
    }

    /**
     * Проверка доступности email
     */
    public boolean isEmailAvailable(String email) {
        return !userRepository.existsByEmail(email);
    }

    /**
     * Валидация данных регистрации
     */
    public String validateRegistrationData(RegisterRequest request) {
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            return "Passwords do not match";
        }

        if (request.getPassword().length() < 6) {
            return "Password must be at least 6 characters";
        }

        if (!isEmailAvailable(request.getEmail())) {
            return "Email already exists";
        }

        return null; // Нет ошибок
    }
}