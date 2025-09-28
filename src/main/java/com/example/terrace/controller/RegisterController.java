package com.example.terrace.controller;

import com.example.terrace.dto.user.LoginResponse;
import com.example.terrace.dto.user.RegisterRequest;
import com.example.terrace.service.RegisterService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/register")
public class RegisterController {

    private final RegisterService registerService;

    @GetMapping
    public String showRegisterForm(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest());
        return "register-form";
    }

    @PostMapping
    public String register(
            @Valid @ModelAttribute("registerRequest") RegisterRequest registerRequest,
            BindingResult bindingResult,
            Model model,
            RedirectAttributes redirectAttributes) {

        // Проверка validation ошибок
        if (bindingResult.hasErrors()) {
            return "register-form";
        }

        // Регистрация через сервис
        LoginResponse response = registerService.register(registerRequest);

        if (response.getUser() != null) {
            // Успешная регистрация
            redirectAttributes.addFlashAttribute("successMessage",
                    "Registration successful! Please login.");
            return "redirect:/login";
        } else {
            // Ошибка регистрации
            model.addAttribute("errorMessage", response.getMessage());
            return "register-form";
        }
    }
}