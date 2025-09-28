package com.example.terrace.mapper;

import com.example.terrace.dto.user.LoginResponse;
import com.example.terrace.dto.user.RegisterRequest;
import com.example.terrace.model.User;
import com.example.terrace.enums.UserRole;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    /**
     * Преобразует User entity в UserInfo для LoginResponse
     */
    public LoginResponse.UserInfo toUserInfo(User user) {
        if (user == null) {
            return null;
        }

        return new LoginResponse.UserInfo(
                user.getId(),
                user.getEmail(),
                user.getRole()
        );
    }

    /**
     * Создает полный LoginResponse с токеном и информацией о пользователе
     */
    public LoginResponse toLoginResponse(User user, String token, String message) {
        LoginResponse.UserInfo userInfo = toUserInfo(user);
        return new LoginResponse(message, token, userInfo);
    }

    /**
     * Преобразует RegisterRequest в User entity (для регистрации)
     * Пароль должен быть зашифрован отдельно!
     */
    public User toEntity(RegisterRequest registerRequest) {
        if (registerRequest == null) {
            return null;
        }

        User user = new User();
        user.setEmail(registerRequest.getEmail());
        // ВНИМАНИЕ: Пароль НЕ устанавливаем здесь!
        // Он должен быть зашифрован в сервисе
        user.setRole(UserRole.USER); // По умолчанию USER

        return user;
    }

    /**
     * Преобразует RegisterRequest в User entity с зашифрованным паролем
     */
    public User toEntity(RegisterRequest registerRequest, String encodedPassword) {
        if (registerRequest == null) {
            return null;
        }

        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setPassword(encodedPassword); // Уже зашифрованный пароль
        user.setRole(UserRole.USER);

        return user;
    }



    /**
     * Создает простой LoginResponse для случаев с ошибками
     */
    public LoginResponse toErrorResponse(String errorMessage) {
        return new LoginResponse(errorMessage, null, null);
    }

    /**
     * Создает успешный LoginResponse
     */
    public LoginResponse toSuccessResponse(User user, String token) {
        return toLoginResponse(user, token, "Login successful");
    }
}