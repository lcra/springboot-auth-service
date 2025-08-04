package com.luke.auth.integration;

import com.luke.auth.entity.User;
import com.luke.auth.repository.UserRepository;
import com.luke.auth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic integration test to verify the authentication system is working.
 * This test creates a real user and tests JWT token generation.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class BasicAuthIntegrationTest {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    private User testUser;
    
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        
        // Create a simple test user
        testUser = new User();
        testUser.setEmail("test@example.com");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.setPasswordHash(passwordEncoder.encode("password123"));
        testUser.setIsActive(true);
        testUser.setEmailVerified(true);
        
        testUser = userRepository.save(testUser);
    }
    
    @Test
    void jwtTokenGeneration_ShouldCreateValidTokens() {
        String accessToken = jwtService.generateAccessToken(testUser);
        String refreshToken = jwtService.generateRefreshToken(testUser);
        
        // Verify tokens are valid
        assert jwtService.isValidToken(accessToken);
        assert jwtService.isValidToken(refreshToken);
        
        // Verify token types
        assert jwtService.isAccessToken(accessToken);
        assert jwtService.isRefreshToken(refreshToken);
        
        // Verify token contains correct user information
        assert testUser.getEmail().equals(jwtService.extractUsername(accessToken));
        assert testUser.getId().equals(jwtService.extractUserId(accessToken));
    }
}