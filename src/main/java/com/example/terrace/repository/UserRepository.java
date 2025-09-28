package com.example.terrace.repository;

import com.example.terrace.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);


    boolean existsByEmail(@NotBlank(message = "Email is required") @Email(message = "Email should be valid") String email);
}
