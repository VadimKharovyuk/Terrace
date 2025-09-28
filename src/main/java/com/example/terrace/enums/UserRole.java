package com.example.terrace.enums;

import lombok.Getter;

// Перечисление для ролей пользователя
@Getter
public enum UserRole {
    USER("Пользователь"), // Клиент
    ADMIN("Администратор"); // Администратор

    private final String displayName;

    UserRole(String displayName) {
        this.displayName = displayName;
    }
}
