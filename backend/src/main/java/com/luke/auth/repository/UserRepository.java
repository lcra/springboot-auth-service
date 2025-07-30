package com.luke.auth.repository;

import com.luke.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);
    
    Optional<User> findByInvitationToken(String invitationToken);
    
    Optional<User> findByPasswordResetToken(String passwordResetToken);
    
    List<User> findByIsActive(Boolean isActive);
    
    List<User> findByEmailVerified(Boolean emailVerified);
    
    @Query("SELECT u FROM User u WHERE u.invitationExpiresAt < :now AND u.invitationToken IS NOT NULL")
    List<User> findExpiredInvitations(@Param("now") LocalDateTime now);
    
    @Query("SELECT u FROM User u WHERE u.passwordResetExpiresAt < :now AND u.passwordResetToken IS NOT NULL")
    List<User> findExpiredPasswordResets(@Param("now") LocalDateTime now);
    
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    List<User> findByRoleName(@Param("roleName") String roleName);
    
    @Query("SELECT u FROM User u JOIN u.roles r JOIN r.permissions p WHERE p.name = :permissionName")
    List<User> findByPermissionName(@Param("permissionName") String permissionName);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.isActive = true")
    long countActiveUsers();
    
    @Query("SELECT u FROM User u WHERE LOWER(u.firstName) LIKE LOWER(CONCAT('%', :name, '%')) " +
           "OR LOWER(u.lastName) LIKE LOWER(CONCAT('%', :name, '%')) " +
           "OR LOWER(u.email) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<User> searchByName(@Param("name") String name);
}