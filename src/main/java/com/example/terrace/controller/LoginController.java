package com.example.terrace.controller;

import com.example.terrace.dto.user.LoginRequest;
import com.example.terrace.dto.user.LoginResponse;
import com.example.terrace.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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
@RequestMapping("/login")
public class LoginController {

    private final AuthService authService;

    @GetMapping
    public String showLoginForm(Model model) {
        model.addAttribute("loginRequest", new LoginRequest());
        return "login-form";
    }

    @PostMapping
    public String login(
            @Valid @ModelAttribute("loginRequest") LoginRequest loginRequest,
            BindingResult bindingResult,
            Model model,
            HttpServletResponse response,
            RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            return "login-form";
        }

        LoginResponse loginResponse = authService.login(loginRequest);

        if (loginResponse.getToken() != null) {
            // Успешный логин - устанавливаем cookie
            Cookie jwtCookie = new Cookie("jwt-token", loginResponse.getToken());
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(24 * 60 * 60);
            response.addCookie(jwtCookie);

            // Перенаправляем на главную или дашборд
            redirectAttributes.addFlashAttribute("successMessage",
                    "Welcome, " + loginResponse.getUser().getEmail() + "!");
            return "redirect:/dashboard";
        } else {
            model.addAttribute("errorMessage", loginResponse.getMessage());
            return "login-form";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response, RedirectAttributes redirectAttributes) {
        // Очищаем cookie
        Cookie jwtCookie = new Cookie("jwt-token", null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);
        response.addCookie(jwtCookie);

        redirectAttributes.addFlashAttribute("successMessage", "You have been logged out.");
        return "redirect:/login";
    }
}