# System Design

This document outlines the core architecture, authentication flows, token management, and API contracts for the RBAC-based system. It is designed with Spring Boot, PostgreSQL, and JWT authentication.

## 1. Overview

This system implements secure user authentication and role-based access control (RBAC). It supports five distinct user roles with varying levels of access. All authentication and authorization mechanisms are enforced via JWT and Spring Security. Data and permissions are stored in a PostgreSQL database.

## 2. Authentication Flow

### Signup and Invitation

- Admin or Super Admin sends an invite or creates a user via `POST /users`
- The user receives a temporary credential or an invite link
- The user sets their own password on first login

### Login

- The user submits credentials via `POST /auth/login`
- The server validates the credentials against the database
- Upon success, the server issues a JWT containing:
  - user_id
  - role
  - permissions
  - exp (expiration timestamp)

- The JWT is returned to the client and must be included in the Authorization header for subsequent requests

### Auth Middleware

- Validates JWT signature and expiration
- Loads the user context from the JWT
- Checks permissions and role assignments
- Grants or denies access based on role-permission mappings

## 3. Token Management

### Token Format

JWTs are signed using RS256.

Example payload:

```json
{
  "sub": "user_123",
  "role": "admin",
  "permissions": [
    "auth:create_user",
    "data:read"
  ],
  "exp": 1720982400
}
```

### Storage

- Client: JWT access tokens are stored in secure HTTP-only cookies. Refresh tokens are also stored in HTTP-only cookies to prevent access via JavaScript and protect against XSS attacks.
- Server:
  - A refresh token strategy is used to allow session renewal without forcing users to log in frequently.
  - A token blacklist is maintained to support secure logout and early token invalidation.
  - Blacklisted tokens are stored with an expiration timestamp and checked on every request to prevent reuse of invalidated tokens.

## 4. Role and Permission Model

Roles and permissions are stored in PostgreSQL. Each role maps to a defined set of permissions that control access to application features and data.

- Roles include: Super Admin, Admin, Member, Viewer, Guest
- Permissions follow a namespaced pattern such as `auth:create_user`, `data:read`, etc.
- Super Admin has unrestricted access across all resources

## 5. API Contracts

### Auth Endpoints

```http
POST /auth/login
Request: { "email": "user@example.com", "password": "secret" }
Response: { "token": "jwt-token", "expires_in": 3600 }

POST /auth/logout
Request: (JWT in Authorization header)
Response: 204 No Content

POST /auth/refresh
Request: (Refresh token in HTTP-only cookie)
Response: { "token": "new-jwt-token", "expires_in": 3600 }
```

### User Management

```http
GET /users
POST /users
PUT /users/{id}
DELETE /users/{id}
POST /users/{id}/roles
```

### Roles and Permissions

```http
GET /roles
GET /permissions
POST /roles
PUT /roles/{id}
```

### Data Endpoints

```http
GET /data
POST /data
DELETE /data/{id}
```

### Billing Endpoints

```http
GET /billing
PATCH /billing
```

## 6. Frontend and Hosting

- Frontend: React with TypeScript, includes login screen, dashboard, and admin views
- Hosting: Spring Boot application packaged with Docker, deployed to AWS EC2. PostgreSQL hosted on AWS RDS
