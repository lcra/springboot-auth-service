package com.luke.auth.service;

import com.luke.auth.entity.User;
import com.luke.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class AuthenticationService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;
    
    public AuthenticationService(
            UserRepository userRepository,
            JwtService jwtService,
            TokenBlacklistService tokenBlacklistService,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.passwordEncoder = passwordEncoder;
    }
    
    public AuthenticationResponse authenticate(String email, String password) {
        logger.debug("Attempting authentication for email: {}", email);
        
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        
        if (!user.getIsActive()) {
            logger.warn("Authentication failed - user inactive: {}", email);
            throw new DisabledException("User account is disabled");
        }
        
        if (user.getPasswordHash() == null) {
            logger.warn("Authentication failed - no password set: {}", email);
            throw new BadCredentialsException("User must set password via invitation");
        }
        
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            logger.warn("Authentication failed - invalid password: {}", email);
            throw new BadCredentialsException("Invalid credentials");
        }
        
        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        
        logger.info("User authenticated successfully: {}", email);
        
        return new AuthenticationResponse(
            accessToken,
            refreshToken,
            user.getId(),
            user.getEmail(),
            user.getFullName(),
            user.getRoles().stream().map(role -> role.getName()).toList()
        );
    }
    
    public AuthenticationResponse refreshToken(String refreshToken) {
        logger.debug("Attempting token refresh");
        
        if (!jwtService.isValidToken(refreshToken)) {
            logger.warn("Invalid refresh token provided");
            throw new BadCredentialsException("Invalid refresh token");
        }
        
        if (!jwtService.isRefreshToken(refreshToken)) {
            logger.warn("Non-refresh token provided for refresh");
            throw new BadCredentialsException("Token is not a refresh token");
        }
        
        if (!tokenBlacklistService.isTokenValid(refreshToken)) {
            logger.warn("Blacklisted refresh token used");
            throw new BadCredentialsException("Token has been invalidated");
        }
        
        String email = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        
        if (!user.getIsActive()) {
            logger.warn("Token refresh failed - user inactive: {}", email);
            throw new DisabledException("User account is disabled");
        }
        
        // Blacklist the old refresh token
        tokenBlacklistService.blacklistToken(refreshToken, "Token refresh");
        
        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);
        
        logger.info("Token refreshed successfully for user: {}", email);
        
        return new AuthenticationResponse(
            newAccessToken,
            newRefreshToken,
            user.getId(),
            user.getEmail(),
            user.getFullName(),
            user.getRoles().stream().map(role -> role.getName()).toList()
        );
    }
    
    public void logout(String token) {
        logger.debug("Processing logout");
        
        if (jwtService.isValidToken(token)) {
            String email = jwtService.extractUsername(token);
            tokenBlacklistService.blacklistToken(token, "User logout");
            logger.info("User logged out successfully: {}", email);
        } else {
            logger.debug("Invalid token provided for logout");
        }
    }
    
    public void logoutAllDevices(Long userId) {
        logger.debug("Processing logout from all devices for user: {}", userId);
        
        tokenBlacklistService.blacklistAllUserTokens(userId, "Logout all devices");
        logger.info("User logged out from all devices: {}", userId);
    }
    
    public boolean setPassword(String invitationToken, String newPassword) {
        logger.debug("Processing password setup with invitation token");
        
        User user = userRepository.findByInvitationToken(invitationToken)
            .orElseThrow(() -> new BadCredentialsException("Invalid invitation token"));
        
        if (user.getInvitationExpiresAt().isBefore(LocalDateTime.now())) {
            logger.warn("Expired invitation token used: {}", user.getEmail());
            throw new BadCredentialsException("Invitation token has expired");
        }
        
        if (!user.getIsActive()) {
            logger.warn("Password setup attempted for inactive user: {}", user.getEmail());
            throw new DisabledException("User account is disabled");
        }
        
        // Set password and clear invitation token
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setInvitationToken(null);
        user.setInvitationExpiresAt(null);
        user.setEmailVerified(true);
        
        userRepository.save(user);
        
        logger.info("Password set successfully for user: {}", user.getEmail());
        return true;
    }
    
    public String generatePasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        
        String resetToken = UUID.randomUUID().toString();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetExpiresAt(LocalDateTime.now().plusHours(1)); // 1 hour expiration
        
        userRepository.save(user);
        
        logger.info("Password reset token generated for user: {}", email);
        return resetToken;
    }
    
    public boolean resetPassword(String resetToken, String newPassword) {
        User user = userRepository.findByPasswordResetToken(resetToken)
            .orElseThrow(() -> new BadCredentialsException("Invalid password reset token"));
        
        if (user.getPasswordResetExpiresAt().isBefore(LocalDateTime.now())) {
            logger.warn("Expired password reset token used: {}", user.getEmail());
            throw new BadCredentialsException("Password reset token has expired");
        }
        
        // Blacklist all existing tokens for security
        tokenBlacklistService.blacklistAllUserTokens(user.getId(), "Password reset");
        
        // Set new password and clear reset token
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetExpiresAt(null);
        
        userRepository.save(user);
        
        logger.info("Password reset successfully for user: {}", user.getEmail());
        return true;
    }
    
    public User getCurrentUser(String token) {
        if (!tokenBlacklistService.isTokenValid(token)) {
            throw new BadCredentialsException("Invalid or blacklisted token");
        }
        
        String email = jwtService.extractUsername(token);
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
    }
    
    public Map<String, Object> getTokenInfo(String token) {
        if (!tokenBlacklistService.isTokenValid(token)) {
            throw new BadCredentialsException("Invalid or blacklisted token");
        }
        
        return jwtService.getTokenInfo(token);
    }
    
    public static class AuthenticationResponse {
        private final String accessToken;
        private final String refreshToken;
        private final Long userId;
        private final String email;
        private final String fullName;
        private final java.util.List<String> roles;
        
        public AuthenticationResponse(String accessToken, String refreshToken, Long userId, 
                                    String email, String fullName, java.util.List<String> roles) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.userId = userId;
            this.email = email;
            this.fullName = fullName;
            this.roles = roles;
        }
        
        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public Long getUserId() { return userId; }
        public String getEmail() { return email; }
        public String getFullName() { return fullName; }
        public java.util.List<String> getRoles() { return roles; }
    }
}