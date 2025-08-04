package com.luke.auth.util;

import com.luke.auth.entity.Permission;
import com.luke.auth.entity.Role;
import com.luke.auth.entity.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

public class TestDataFactory {
    
    public static User createTestUser(String email, String password, PasswordEncoder passwordEncoder) {
        User user = new User();
        user.setEmail(email);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setIsActive(true);
        user.setEmailVerified(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        return user;
    }
    
    public static User createInactiveUser(String email, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, "password123", passwordEncoder);
        user.setIsActive(false);
        return user;
    }
    
    public static User createUnverifiedUser(String email, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, "password123", passwordEncoder);
        user.setEmailVerified(false);
        return user;
    }
    
    public static User createUserWithInvitation(String email) {
        User user = new User();
        user.setEmail(email);
        user.setFirstName("Invited");
        user.setLastName("User");
        user.setIsActive(true);
        user.setEmailVerified(false);
        user.setInvitationToken(UUID.randomUUID().toString());
        user.setInvitationExpiresAt(LocalDateTime.now().plusDays(7));
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        return user;
    }
    
    public static User createUserWithExpiredInvitation(String email) {
        User user = createUserWithInvitation(email);
        user.setInvitationExpiresAt(LocalDateTime.now().minusDays(1));
        return user;
    }
    
    public static User createUserWithPasswordReset(String email, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, "oldpassword", passwordEncoder);
        user.setPasswordResetToken(UUID.randomUUID().toString());
        user.setPasswordResetExpiresAt(LocalDateTime.now().plusHours(1));
        return user;
    }
    
    public static Permission createPermission(String name, String description, String category) {
        Permission permission = new Permission();
        permission.setName(name);
        permission.setDescription(description);
        permission.setCategory(category);
        permission.setCreatedAt(LocalDateTime.now());
        permission.setUpdatedAt(LocalDateTime.now());
        return permission;
    }
    
    public static Role createRole(String name, String description, Boolean isSystemRole) {
        Role role = new Role();
        role.setName(name);
        role.setDescription(description);
        role.setIsSystemRole(isSystemRole);
        role.setCreatedAt(LocalDateTime.now());
        role.setUpdatedAt(LocalDateTime.now());
        return role;
    }
    
    public static Role createAdminRole() {
        Role role = createRole("ADMIN", "Administrator role", true);
        
        // Add common admin permissions
        role.getPermissions().addAll(Set.of(
            createPermission("auth:create_user", "Create users", "auth"),
            createPermission("auth:update_user", "Update users", "auth"),
            createPermission("auth:view_users", "View users", "auth"),
            createPermission("data:read", "Read data", "data"),
            createPermission("data:write", "Write data", "data")
        ));
        
        return role;
    }
    
    public static Role createMemberRole() {
        Role role = createRole("MEMBER", "Member role", true);
        
        role.getPermissions().addAll(Set.of(
            createPermission("auth:view_users", "View users", "auth"),
            createPermission("data:read", "Read data", "data")
        ));
        
        return role;
    }
    
    public static Role createViewerRole() {
        Role role = createRole("VIEWER", "Viewer role", true);
        
        role.getPermissions().addAll(Set.of(
            createPermission("data:read", "Read data", "data")
        ));
        
        return role;
    }
    
    public static User createAdminUser(String email, String password, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, password, passwordEncoder);
        Role adminRole = createAdminRole();
        user.addRole(adminRole);
        return user;
    }
    
    public static User createMemberUser(String email, String password, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, password, passwordEncoder);
        Role memberRole = createMemberRole();
        user.addRole(memberRole);
        return user;
    }
    
    public static User createViewerUser(String email, String password, PasswordEncoder passwordEncoder) {
        User user = createTestUser(email, password, passwordEncoder);
        Role viewerRole = createViewerRole();
        user.addRole(viewerRole);
        return user;
    }
}