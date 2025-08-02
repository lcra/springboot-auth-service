package com.luke.auth.controller;

import com.luke.auth.entity.User;
import com.luke.auth.service.AuthenticationService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    private static final int ACCESS_TOKEN_COOKIE_MAX_AGE = 15 * 60; // 15 minutes
    private static final int REFRESH_TOKEN_COOKIE_MAX_AGE = 24 * 60 * 60; // 24 hours
    
    private final AuthenticationService authenticationService;
    
    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, 
                                             HttpServletResponse response) {
        try {
            logger.info("Login attempt for email: {}", request.email);
            
            AuthenticationService.AuthenticationResponse authResponse = 
                authenticationService.authenticate(request.email, request.password);
            
            // Set HTTP-only cookies for tokens
            setTokenCookies(response, authResponse.getAccessToken(), authResponse.getRefreshToken());
            
            LoginResponse loginResponse = new LoginResponse(
                "Login successful",
                authResponse.getUserId(),
                authResponse.getEmail(),
                authResponse.getFullName(),
                authResponse.getRoles()
            );
            
            return ResponseEntity.ok(loginResponse);
            
        } catch (Exception e) {
            logger.warn("Login failed for email: {} - {}", request.email, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new LoginResponse("Invalid credentials", null, null, null, null));
        }
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponse> refreshToken(HttpServletRequest request, 
                                                           HttpServletResponse response) {
        try {
            String refreshToken = extractRefreshTokenFromCookies(request);
            
            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new RefreshTokenResponse("Refresh token not provided", null, null));
            }
            
            AuthenticationService.AuthenticationResponse authResponse = 
                authenticationService.refreshToken(refreshToken);
            
            // Set new HTTP-only cookies
            setTokenCookies(response, authResponse.getAccessToken(), authResponse.getRefreshToken());
            
            RefreshTokenResponse refreshResponse = new RefreshTokenResponse(
                "Token refreshed successfully",
                authResponse.getUserId(),
                authResponse.getEmail()
            );
            
            return ResponseEntity.ok(refreshResponse);
            
        } catch (Exception e) {
            logger.warn("Token refresh failed: {}", e.getMessage());
            clearTokenCookies(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new RefreshTokenResponse("Invalid refresh token", null, null));
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, 
                                                     HttpServletResponse response) {
        try {
            String accessToken = extractAccessTokenFromCookies(request);
            
            if (accessToken != null) {
                authenticationService.logout(accessToken);
            }
            
            clearTokenCookies(response);
            
            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
            
        } catch (Exception e) {
            logger.error("Logout error: {}", e.getMessage());
            clearTokenCookies(response);
            return ResponseEntity.ok(Map.of("message", "Logged out"));
        }
    }
    
    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, String>> logoutAll(Authentication authentication, 
                                                        HttpServletResponse response) {
        try {
            if (authentication != null && authentication.getPrincipal() instanceof 
                com.luke.auth.service.CustomUserDetailsService.CustomUserPrincipal userPrincipal) {
                
                authenticationService.logoutAllDevices(userPrincipal.getUserId());
                clearTokenCookies(response);
                
                return ResponseEntity.ok(Map.of("message", "Logged out from all devices"));
            }
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Authentication required"));
            
        } catch (Exception e) {
            logger.error("Logout all devices error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Logout failed"));
        }
    }
    
    @PostMapping("/set-password")
    public ResponseEntity<Map<String, String>> setPassword(@Valid @RequestBody SetPasswordRequest request) {
        try {
            boolean success = authenticationService.setPassword(request.invitationToken, request.password);
            
            if (success) {
                return ResponseEntity.ok(Map.of("message", "Password set successfully"));
            } else {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to set password"));
            }
            
        } catch (Exception e) {
            logger.warn("Set password failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try {
            String resetToken = authenticationService.generatePasswordResetToken(request.email);
            
            // In a real application, you would send this token via email
            logger.info("Password reset token generated for email: {} (token would be sent via email)", request.email);
            
            return ResponseEntity.ok(Map.of(
                "message", "Password reset instructions sent to your email",
                "resetToken", resetToken // Remove this in production - only for testing
            ));
            
        } catch (Exception e) {
            logger.warn("Forgot password failed for email: {} - {}", request.email, e.getMessage());
            // Return success message even if email doesn't exist (security best practice)
            return ResponseEntity.ok(Map.of("message", "Password reset instructions sent to your email"));
        }
    }
    
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            boolean success = authenticationService.resetPassword(request.resetToken, request.newPassword);
            
            if (success) {
                return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
            } else {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Failed to reset password"));
            }
            
        } catch (Exception e) {
            logger.warn("Password reset failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", e.getMessage()));
        }
    }
    
    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> getCurrentUser(Authentication authentication) {
        try {
            if (authentication != null && authentication.getPrincipal() instanceof 
                com.luke.auth.service.CustomUserDetailsService.CustomUserPrincipal userPrincipal) {
                
                User user = userPrincipal.getUser();
                
                UserInfoResponse userInfo = new UserInfoResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.getFullName(),
                    user.getIsActive(),
                    user.getEmailVerified(),
                    user.getRoles().stream().map(role -> role.getName()).toList(),
                    user.getRoles().stream()
                        .flatMap(role -> role.getPermissions().stream())
                        .map(permission -> permission.getName())
                        .distinct()
                        .toList()
                );
                
                return ResponseEntity.ok(userInfo);
            }
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            logger.error("Get current user failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    @GetMapping("/token-info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(HttpServletRequest request) {
        try {
            String accessToken = extractAccessTokenFromCookies(request);
            
            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Access token not provided"));
            }
            
            Map<String, Object> tokenInfo = authenticationService.getTokenInfo(accessToken);
            return ResponseEntity.ok(tokenInfo);
            
        } catch (Exception e) {
            logger.warn("Get token info failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid token"));
        }
    }
    
    // Utility methods
    private void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access token cookie (short-lived)
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE_NAME, accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production with HTTPS
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(ACCESS_TOKEN_COOKIE_MAX_AGE);
        response.addCookie(accessTokenCookie);
        
        // Refresh token cookie (long-lived)
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // Set to true in production with HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(REFRESH_TOKEN_COOKIE_MAX_AGE);
        response.addCookie(refreshTokenCookie);
    }
    
    private void clearTokenCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE_NAME, "");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);
        
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);
    }
    
    private String extractAccessTokenFromCookies(HttpServletRequest request) {
        return extractTokenFromCookies(request, ACCESS_TOKEN_COOKIE_NAME);
    }
    
    private String extractRefreshTokenFromCookies(HttpServletRequest request) {
        return extractTokenFromCookies(request, REFRESH_TOKEN_COOKIE_NAME);
    }
    
    private String extractTokenFromCookies(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
    
    // Request/Response DTOs
    public static class LoginRequest {
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        public String email;
        
        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        public String password;
    }
    
    public static class LoginResponse {
        public String message;
        public Long userId;
        public String email;
        public String fullName;
        public java.util.List<String> roles;
        
        public LoginResponse(String message, Long userId, String email, String fullName, java.util.List<String> roles) {
            this.message = message;
            this.userId = userId;
            this.email = email;
            this.fullName = fullName;
            this.roles = roles;
        }
    }
    
    public static class RefreshTokenResponse {
        public String message;
        public Long userId;
        public String email;
        
        public RefreshTokenResponse(String message, Long userId, String email) {
            this.message = message;
            this.userId = userId;
            this.email = email;
        }
    }
    
    public static class SetPasswordRequest {
        @NotBlank(message = "Invitation token is required")
        public String invitationToken;
        
        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        public String password;
    }
    
    public static class ForgotPasswordRequest {
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        public String email;
    }
    
    public static class ResetPasswordRequest {
        @NotBlank(message = "Reset token is required")
        public String resetToken;
        
        @NotBlank(message = "New password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        public String newPassword;
    }
    
    public static class UserInfoResponse {
        public Long id;
        public String email;
        public String firstName;
        public String lastName;
        public String fullName;
        public Boolean isActive;
        public Boolean emailVerified;
        public java.util.List<String> roles;
        public java.util.List<String> permissions;
        
        public UserInfoResponse(Long id, String email, String firstName, String lastName, String fullName,
                              Boolean isActive, Boolean emailVerified, java.util.List<String> roles, java.util.List<String> permissions) {
            this.id = id;
            this.email = email;
            this.firstName = firstName;
            this.lastName = lastName;
            this.fullName = fullName;
            this.isActive = isActive;
            this.emailVerified = emailVerified;
            this.roles = roles;
            this.permissions = permissions;
        }
    }
}