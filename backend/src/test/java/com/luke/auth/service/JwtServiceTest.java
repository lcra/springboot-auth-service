package com.luke.auth.service;

import com.luke.auth.entity.User;
import com.luke.auth.util.TestDataFactory;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class JwtServiceTest {
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    private User testUser;
    
    @BeforeEach
    void setUp() {
        testUser = TestDataFactory.createAdminUser("test@example.com", "password123", passwordEncoder);
        testUser.setId(1L); // Set a test ID
    }
    
    @Test
    void generateAccessToken_ShouldCreateValidToken() {
        String token = jwtService.generateAccessToken(testUser);
        
        assertNotNull(token);
        assertTrue(jwtService.isValidToken(token));
        assertTrue(jwtService.isAccessToken(token));
        assertFalse(jwtService.isRefreshToken(token));
        assertFalse(jwtService.isTokenExpired(token));
    }
    
    @Test
    void generateRefreshToken_ShouldCreateValidToken() {
        String token = jwtService.generateRefreshToken(testUser);
        
        assertNotNull(token);
        assertTrue(jwtService.isValidToken(token));
        assertTrue(jwtService.isRefreshToken(token));
        assertFalse(jwtService.isAccessToken(token));
        assertFalse(jwtService.isTokenExpired(token));
    }
    
    @Test
    void extractUsername_ShouldReturnCorrectEmail() {
        String token = jwtService.generateAccessToken(testUser);
        String extractedUsername = jwtService.extractUsername(token);
        
        assertEquals(testUser.getEmail(), extractedUsername);
    }
    
    @Test
    void extractUserId_ShouldReturnCorrectId() {
        String token = jwtService.generateAccessToken(testUser);
        Long extractedUserId = jwtService.extractUserId(token);
        
        assertEquals(testUser.getId(), extractedUserId);
    }
    
    @Test
    void extractJti_ShouldReturnUniqueId() {
        String token1 = jwtService.generateAccessToken(testUser);
        String token2 = jwtService.generateAccessToken(testUser);
        
        String jti1 = jwtService.extractJti(token1);
        String jti2 = jwtService.extractJti(token2);
        
        assertNotNull(jti1);
        assertNotNull(jti2);
        assertNotEquals(jti1, jti2); // Each token should have unique JTI
    }
    
    @Test
    void extractTokenType_ShouldReturnCorrectType() {
        String accessToken = jwtService.generateAccessToken(testUser);
        String refreshToken = jwtService.generateRefreshToken(testUser);
        
        assertEquals("access", jwtService.extractTokenType(accessToken));
        assertEquals("refresh", jwtService.extractTokenType(refreshToken));
    }
    
    @Test
    void extractExpiration_ShouldReturnFutureDate() {
        String token = jwtService.generateAccessToken(testUser);
        LocalDateTime expiration = jwtService.extractExpirationAsLocalDateTime(token);
        
        assertTrue(expiration.isAfter(LocalDateTime.now()));
    }
    
    @Test
    void getTokenInfo_ShouldReturnCompleteTokenDetails() {
        String token = jwtService.generateAccessToken(testUser);
        Map<String, Object> tokenInfo = jwtService.getTokenInfo(token);
        
        assertNotNull(tokenInfo.get("jti"));
        assertEquals(testUser.getEmail(), tokenInfo.get("subject"));
        assertEquals(testUser.getId(), tokenInfo.get("userId"));
        assertEquals("access", tokenInfo.get("tokenType"));
        assertNotNull(tokenInfo.get("roles"));
        assertNotNull(tokenInfo.get("permissions"));
        assertNotNull(tokenInfo.get("issuedAt"));
        assertNotNull(tokenInfo.get("expiresAt"));
        assertNotNull(tokenInfo.get("issuer"));
    }
    
    @Test
    void isValidToken_WithInvalidToken_ShouldReturnFalse() {
        assertFalse(jwtService.isValidToken("invalid-token"));
        assertFalse(jwtService.isValidToken(""));
        assertFalse(jwtService.isValidToken(null));
    }
    
    @Test
    void isValidToken_WithMalformedToken_ShouldReturnFalse() {
        String malformedToken = "header.payload"; // Missing signature
        assertFalse(jwtService.isValidToken(malformedToken));
    }
    
    @Test
    void extractClaims_WithInvalidToken_ShouldThrowException() {
        assertThrows(MalformedJwtException.class, () -> {
            jwtService.extractClaims("invalid-token");
        });
    }
    
    @Test
    void extractClaims_WithMalformedToken_ShouldThrowException() {
        assertThrows(MalformedJwtException.class, () -> {
            jwtService.extractClaims("header.payload.signature");
        });
    }
    
    @Test
    void isTokenExpired_WithValidToken_ShouldReturnFalse() {
        String token = jwtService.generateAccessToken(testUser);
        assertFalse(jwtService.isTokenExpired(token));
    }
    
    @Test
    void tokenShouldContainRolesAndPermissions() {
        String token = jwtService.generateAccessToken(testUser);
        Map<String, Object> tokenInfo = jwtService.getTokenInfo(token);
        
        String roles = (String) tokenInfo.get("roles");
        String permissions = (String) tokenInfo.get("permissions");
        
        assertNotNull(roles);
        assertNotNull(permissions);
        assertTrue(roles.contains("ADMIN"));
        assertTrue(permissions.contains("auth:"));
    }
    
    @Test
    void tokenShouldContainUserMetadata() {
        String token = jwtService.generateAccessToken(testUser);
        Map<String, Object> tokenInfo = jwtService.getTokenInfo(token);
        
        assertEquals(testUser.getId(), tokenInfo.get("userId"));
        assertEquals(testUser.getEmail(), tokenInfo.get("subject"));
    }
    
    @Test
    void isAccessToken_WithRefreshToken_ShouldReturnFalse() {
        String refreshToken = jwtService.generateRefreshToken(testUser);
        assertFalse(jwtService.isAccessToken(refreshToken));
    }
    
    @Test
    void isRefreshToken_WithAccessToken_ShouldReturnFalse() {
        String accessToken = jwtService.generateAccessToken(testUser);
        assertFalse(jwtService.isRefreshToken(accessToken));
    }
    
    @Test
    void differentUsersCreateDifferentTokens() {
        User user1 = TestDataFactory.createTestUser("user1@example.com", "password", passwordEncoder);
        user1.setId(1L);
        User user2 = TestDataFactory.createTestUser("user2@example.com", "password", passwordEncoder);
        user2.setId(2L);
        
        String token1 = jwtService.generateAccessToken(user1);
        String token2 = jwtService.generateAccessToken(user2);
        
        assertNotEquals(token1, token2);
        assertEquals(user1.getEmail(), jwtService.extractUsername(token1));
        assertEquals(user2.getEmail(), jwtService.extractUsername(token2));
        assertEquals(user1.getId(), jwtService.extractUserId(token1));
        assertEquals(user2.getId(), jwtService.extractUserId(token2));
    }
}