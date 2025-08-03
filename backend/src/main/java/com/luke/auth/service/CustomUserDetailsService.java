package com.luke.auth.service;

import com.luke.auth.entity.User;
import com.luke.auth.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Service
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        
        return new CustomUserPrincipal(user);
    }
    
    public static class CustomUserPrincipal implements UserDetails {
        private final User user;
        private final Set<GrantedAuthority> authorities;
        
        public CustomUserPrincipal(User user) {
            this.user = user;
            this.authorities = buildAuthorities(user);
        }
        
        private Set<GrantedAuthority> buildAuthorities(User user) {
            Set<GrantedAuthority> authorities = new HashSet<>();
            
            // Add role authorities
            user.getRoles().forEach(role -> {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
                
                // Add permission authorities
                role.getPermissions().forEach(permission -> {
                    authorities.add(new SimpleGrantedAuthority(permission.getName()));
                });
            });
            
            return authorities;
        }
        
        public User getUser() {
            return user;
        }
        
        public Long getUserId() {
            return user.getId();
        }
        
        public String getFullName() {
            return user.getFullName();
        }
        
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }
        
        @Override
        public String getPassword() {
            return user.getPasswordHash();
        }
        
        @Override
        public String getUsername() {
            return user.getEmail();
        }
        
        @Override
        public boolean isAccountNonExpired() {
            return true;
        }
        
        @Override
        public boolean isAccountNonLocked() {
            return true;
        }
        
        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }
        
        @Override
        public boolean isEnabled() {
            return user.getIsActive() && user.getEmailVerified();
        }
        
        public boolean hasRole(String roleName) {
            return authorities.contains(new SimpleGrantedAuthority("ROLE_" + roleName));
        }
        
        public boolean hasPermission(String permission) {
            return authorities.contains(new SimpleGrantedAuthority(permission));
        }
    }
}