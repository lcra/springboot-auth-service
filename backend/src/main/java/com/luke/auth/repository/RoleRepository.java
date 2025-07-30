package com.luke.auth.repository;

import com.luke.auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    Optional<Role> findByName(String name);
    
    boolean existsByName(String name);
    
    List<Role> findByIsSystemRole(Boolean isSystemRole);
    
    @Query("SELECT r FROM Role r JOIN r.permissions p WHERE p.name = :permissionName")
    List<Role> findByPermissionName(@Param("permissionName") String permissionName);
    
    @Query("SELECT r FROM Role r WHERE r.isSystemRole = false")
    List<Role> findCustomRoles();
    
    @Query("SELECT r FROM Role r WHERE r.isSystemRole = true")
    List<Role> findSystemRoles();
    
    @Query("SELECT COUNT(r) FROM Role r WHERE r.isSystemRole = false")
    long countCustomRoles();
    
    @Query("SELECT r FROM Role r WHERE LOWER(r.name) LIKE LOWER(CONCAT('%', :name, '%')) " +
           "OR LOWER(r.description) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<Role> searchByName(@Param("name") String name);
}