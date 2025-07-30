package com.luke.auth.repository;

import com.luke.auth.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    
    Optional<TokenBlacklist> findByJti(String jti);
    
    boolean existsByJti(String jti);
    
    List<TokenBlacklist> findByUserId(Long userId);
    
    List<TokenBlacklist> findByTokenType(String tokenType);
    
    @Query("SELECT t FROM TokenBlacklist t WHERE t.userId = :userId AND t.tokenType = :tokenType")
    List<TokenBlacklist> findByUserIdAndTokenType(@Param("userId") Long userId, @Param("tokenType") String tokenType);
    
    @Query("SELECT t FROM TokenBlacklist t WHERE t.expiresAt < :now")
    List<TokenBlacklist> findExpiredTokens(@Param("now") LocalDateTime now);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM TokenBlacklist t WHERE t.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM TokenBlacklist t WHERE t.userId = :userId")
    int deleteAllUserTokens(@Param("userId") Long userId);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM TokenBlacklist t WHERE t.userId = :userId AND t.tokenType = :tokenType")
    int deleteUserTokensByType(@Param("userId") Long userId, @Param("tokenType") String tokenType);
    
    @Query("SELECT COUNT(t) FROM TokenBlacklist t WHERE t.userId = :userId")
    long countByUserId(@Param("userId") Long userId);
    
    @Query("SELECT COUNT(t) FROM TokenBlacklist t WHERE t.tokenType = :tokenType")
    long countByTokenType(@Param("tokenType") String tokenType);
}