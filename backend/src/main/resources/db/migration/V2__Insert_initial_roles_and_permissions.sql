-- V2__Insert_initial_roles_and_permissions.sql
-- Insert initial roles and permissions for RBAC system

-- Insert permissions
INSERT INTO permissions (name, description, category) VALUES
-- Auth permissions
('auth:create_user', 'Create new users and send invitations', 'auth'),
('auth:update_user', 'Update user information and status', 'auth'),
('auth:delete_user', 'Delete users from the system', 'auth'),
('auth:view_users', 'View user list and details', 'auth'),
('auth:manage_roles', 'Assign and remove user roles', 'auth'),
('auth:view_roles', 'View available roles and permissions', 'auth'),
('auth:create_roles', 'Create new custom roles', 'auth'),
('auth:update_roles', 'Modify role permissions', 'auth'),
('auth:delete_roles', 'Delete custom roles', 'auth'),

-- Data permissions
('data:read', 'Read data entries', 'data'),
('data:write', 'Create and update data entries', 'data'),
('data:delete', 'Delete data entries', 'data'),
('data:export', 'Export data in various formats', 'data'),
('data:import', 'Import data from external sources', 'data'),

-- Billing permissions
('billing:view', 'View billing information and plans', 'billing'),
('billing:manage', 'Manage billing plans and payment methods', 'billing'),
('billing:view_usage', 'View usage statistics and metrics', 'billing'),

-- System permissions
('system:admin', 'Full system administration access', 'system');

-- Insert roles
INSERT INTO roles (name, description, is_system_role) VALUES
('SUPER_ADMIN', 'Super Administrator with full system access', true),
('ADMIN', 'Administrator with user and data management capabilities', true),
('MEMBER', 'Regular member with data access and limited management', true),
('VIEWER', 'Read-only access to data and basic information', true),
('GUEST', 'Limited access for guest users', true);

-- Assign permissions to roles
-- SUPER_ADMIN gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'SUPER_ADMIN';

-- ADMIN permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'ADMIN' 
AND p.name IN (
    'auth:create_user', 'auth:update_user', 'auth:view_users', 'auth:manage_roles', 'auth:view_roles',
    'data:read', 'data:write', 'data:delete', 'data:export', 'data:import',
    'billing:view', 'billing:view_usage'
);

-- MEMBER permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'MEMBER' 
AND p.name IN (
    'auth:view_users', 'auth:view_roles',
    'data:read', 'data:write', 'data:export',
    'billing:view'
);

-- VIEWER permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'VIEWER' 
AND p.name IN (
    'auth:view_users', 'auth:view_roles',
    'data:read',
    'billing:view'
);

-- GUEST permissions (minimal)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'GUEST' 
AND p.name IN (
    'data:read'
);