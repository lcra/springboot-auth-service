# User Roles and Permissions

This document outlines the Role-Based Access Control (RBAC) model for the system. Permissions are granted based on roles, with each role encapsulating a predefined set of capabilities.

---

## Roles

**Super Admin**  
Full access to all system resources and configuration, including user, role, and permission management.

**Admin**  
Responsible for managing users and data within their organization or scope. Limited to non-global settings.

**Member**  
Standard user with permission to create and manage their own data. Cannot access administrative features.

**Viewer**  
Read-only access to system data. Cannot make modifications.

**Guest**  
Temporary or external user with minimal, scoped read access.

---

## Permissions

Below is a list of all available permissions the system may enforce. These are grouped by domain for clarity.

- **Authentication & User Management**
  - `auth:create_user` — Create new users
  - `auth:update_user` — Update existing user info
  - `auth:delete_user` — Delete users
  - `auth:assign_roles` — Assign roles to users

- **Data Access**
  - `data:read` — Read access to data
  - `data:write` — Write access to data
  - `data:delete` — Delete data

- **Billing**
  - `billing:view` — View billing details
  - `billing:manage` — Modify billing or payment settings

---

## Role → Permissions Mapping (YAML)

```yaml
super_admin:
  - "*"

admin:
  - auth:create_user
  - auth:update_user
  - auth:delete_user
  - auth:assign_roles
  - data:read
  - data:write
  - data:delete
  - billing:view
  - billing:manage

member:
  - data:read
  - data:write

viewer:
  - data:read

guest:
  - data:read