# User Stories — Role-Based Access Control (RBAC)

This document outlines user stories for each permission defined in the RBAC system. Each story is written to express the value each permission provides, and how users interact with them based on their role.

---

## Authentication & User Management

### `auth:create_user`
> **As** an Admin or Super Admin  
> **I want to** create new users  
> **So that** I can onboard team members or external collaborators

### `auth:update_user`
> **As** an Admin or Super Admin  
> **I want to** update user information  
> **So that** user profiles remain accurate and up-to-date

### `auth:delete_user`
> **As** an Admin or Super Admin  
> **I want to** delete users  
> **So that** I can revoke access when users leave or no longer require access

### `auth:assign_roles`
> **As** an Admin or Super Admin  
> **I want to** assign roles to users  
> **So that** they have the appropriate access levels based on responsibilities

---

## Data Access

### `data:read`
> **As** a user with read access (Member, Viewer, Guest)  
> **I want to** view data  
> **So that** I can stay informed, monitor progress, or extract insights

### `data:write`
> **As** a user with write access (Member, Admin, Super Admin)  
> **I want to** create or update data  
> **So that** I can contribute to or maintain accurate system information

### `data:delete`
> **As** a user with delete access (Admin, Super Admin)  
> **I want to** delete outdated or invalid data  
> **So that** the system remains clean and relevant

---

## Billing

### `billing:view`
> **As** an Admin or Super Admin  
> **I want to** view billing information  
> **So that** I can track usage, understand costs, and manage financial planning

### `billing:manage`
> **As** an Admin or Super Admin  
> **I want to** update billing settings or payment methods  
> **So that** the account stays active and properly configured