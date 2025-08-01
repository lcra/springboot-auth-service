package com.luke.auth.service;

import com.luke.auth.entity.TokenBlacklist;
import com.luke.auth.repository.TokenBlacklistRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Transactional
public class TokenBlacklistService {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklistService.class);
    
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final JwtService jwtService;
    
    public TokenBlacklistService(TokenBlacklistRepository tokenBlacklistRepository, JwtService jwtService) {
        this.tokenBlacklistRepository = tokenBlacklistRepository;
        this.jwtService = jwtService;
    }
    
    public void blacklistToken(String token, String reason) {
        try {
            String jti = jwtService.extractJti(token);
            Long userId = jwtService.extractUserId(token);
            String tokenType = jwtService.extractTokenType(token);
            LocalDateTime expiresAt = jwtService.extractExpirationAsLocalDateTime(token);
            
            if (!isTokenBlacklisted(jti)) {
                TokenBlacklist blacklistEntry = new TokenBlacklist(jti, userId, tokenType, expiresAt, reason);
                tokenBlacklistRepository.save(blacklistEntry);
                logger.info("Token blacklisted: jti={}, userId={}, tokenType={}, reason={}", 
                    jti, userId, tokenType, reason);
            } else {
                logger.debug("Token already blacklisted: jti={}", jti);
            }
        } catch (Exception e) {
            logger.error("Failed to blacklist token", e);
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }
    
    public void blacklistToken(String token) {
        blacklistToken(token, "Manual blacklist");
    }
    
    public boolean isTokenBlacklisted(String jti) {
        return tokenBlacklistRepository.existsByJti(jti);
    }
    
    public boolean isTokenValid(String token) {
        if (!jwtService.isValidToken(token)) {
            return false;
        }
        
        try {
            String jti = jwtService.extractJti(token);
            return !isTokenBlacklisted(jti);
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    public void blacklistAllUserTokens(Long userId, String reason) {
        List<TokenBlacklist> userTokens = tokenBlacklistRepository.findByUserId(userId);
        int existingCount = userTokens.size();
        
        tokenBlacklistRepository.deleteAllUserTokens(userId);
        logger.info("Blacklisted all tokens for user: userId={}, previousCount={}, reason={}", 
            userId, existingCount, reason);
    }
    
    public void blacklistUserTokensByType(Long userId, String tokenType, String reason) {
        int deletedCount = tokenBlacklistRepository.deleteUserTokensByType(userId, tokenType);
        logger.info("Blacklisted user tokens by type: userId={}, tokenType={}, count={}, reason={}", 
            userId, tokenType, deletedCount, reason);
    }
    
    @Scheduled(fixedRate = 3600000) // Run every hour
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        int deletedCount = tokenBlacklistRepository.deleteExpiredTokens(now);
        
        if (deletedCount > 0) {
            logger.info("Cleaned up expired blacklisted tokens: count={}", deletedCount);
        }
    }
    
    public List<TokenBlacklist> getExpiredTokens() {
        return tokenBlacklistRepository.findExpiredTokens(LocalDateTime.now());
    }
    
    public long getBlacklistedTokenCount() {
        return tokenBlacklistRepository.count();
    }
    
    public long getUserBlacklistedTokenCount(Long userId) {
        return tokenBlacklistRepository.countByUserId(userId);
    }
    
    public List<TokenBlacklist> getUserBlacklistedTokens(Long userId) {
        return tokenBlacklistRepository.findByUserId(userId);
    }
    
    public void forceCleanupExpiredTokens() {
        cleanupExpiredTokens();
    }
}