# API Specification

This document provides detailed request and response formats for all available API endpoints in the system. It assumes JWT-based authentication with role-permission checks enforced on each route.

## Authentication

### POST /auth/set-password

Sets the user's password using a one-time invitation token.

- Auth Required: No
- Permissions: None (token-based)

**Request**

```json
{
  "token": "invitation-token",
  "password": "NewSecurePassword123!"
}
```

**Response (200 OK)**

```json
{
  "message": "Password set successfully",
  "token": "jwt-token"
}
```

**Response (400 Bad Request)**

```json
{
  "error": "Invalid or expired token"
}
```


### POST /auth/login

Authenticate a user and return an access token.

- Auth Required: No
- Permissions: None

**Request**

```json
{
  "email": "user@example.com",
  "password": "secret"
}
```

**Response (200 OK)**

```json
{
  "token": "jwt-token",
  "expires_in": 3600
}
```

**Response (401 Unauthorized)**

```json
{
  "error": "Invalid credentials"
}
```

### POST /auth/logout

Logs the user out by blacklisting the current token.

- Auth Required: Yes
- Permissions: Any authenticated user

**Request**

- JWT in Authorization: Bearer <token> header

**Response (204 No Content)**

### POST /auth/refresh

Generates a new access token using the refresh token.

- Auth Required: Yes (via secure cookie)
- Permissions: Any authenticated user

**Response (200 OK)**

```json
{
  "token": "new-jwt-token",
  "expires_in": 3600
}
```

## User Management

### GET /users

Returns a list of all users.

- Auth Required: Yes
- Permissions: auth:create_user, auth:update_user, etc.

**Response (200 OK)**

```json
[
  {
    "id": "user_123",
    "email": "admin@example.com",
    "roles": ["admin"]
  }
]
```


### POST /users

Creates a new user and sends an invitation link.

- Auth Required: Yes
- Permissions: auth:create_user

**Request**

```json
{
  "email": "newuser@example.com",
  "role": "viewer"
}
```

**Response (201 Created)**

```json
{
  "id": "user_456",
  "email": "newuser@example.com",
  "role": "viewer",
  "invitation_sent": true
}
```

**Notes:**  
- The backend generates a one-time token and sends an invite link to the user's email.  
- The user sets their password using the token via the `/auth/set-password` endpoint.


### PUT /users/{id}

Updates user information.

- Auth Required: Yes
- Permissions: auth:update_user

**Request**

```json
{
  "email": "updated@example.com"
}
```

**Response (200 OK)**

```json
{
  "id": "user_123",
  "email": "updated@example.com"
}
```

### DELETE /users/{id}

Deletes a user.

- Auth Required: Yes
- Permissions: auth:delete_user

**Response (204 No Content)**

### POST /users/{id}/roles

Assigns one or more roles to a user.

- Auth Required: Yes
- Permissions: auth:assign_roles

**Request**

```json
{
  "roles": ["admin"]
}
```

**Response (200 OK)**

```json
{
  "id": "user_123",
  "roles": ["admin"]
}
```

## Roles and Permissions

### GET /roles

Returns a list of available roles.

- Auth Required: Yes
- Permissions: Any authenticated user

**Response**

```json
["super_admin", "admin", "member", "viewer", "guest"]
```

### GET /permissions

Returns all defined permissions.

- Auth Required: Yes
- Permissions: Any authenticated user

**Response**

```json
[
  "auth:create_user",
  "auth:update_user",
  "data:read"
]
```

### POST /roles

Create a new custom role with a set of permissions.

- Auth Required: Yes
- Permissions: Super Admin only (*)

**Request**

```json
{
  "name": "custom_role",
  "permissions": ["data:read", "data:write"]
}
```

**Response**

```json
{
  "id": "role_123",
  "name": "custom_role",
  "permissions": ["data:read", "data:write"]
}
```

### PUT /roles/{id}

Update an existing role.

- Auth Required: Yes
- Permissions: Super Admin only (*)

**Request**

```json
{
  "permissions": ["data:read"]
}
```

**Response**

```json
{
  "id": "role_123",
  "permissions": ["data:read"]
}
```

## Data

### GET /data

Read available data records.

- Auth Required: Yes
- Permissions: data:read

**Response**

```json
[
  {
    "id": "item_1",
    "value": "example"
  }
]
```

### POST /data

Create new data entry.

- Auth Required: Yes
- Permissions: data:write

**Request**

```json
{
  "value": "new data"
}
```

**Response**

```json
{
  "id": "item_2",
  "value": "new data"
}
```

### DELETE /data/{id}

Delete a data record.

- Auth Required: Yes
- Permissions: data:delete

**Response (204 No Content)**

## Billing

### GET /billing

View current billing info.

- Auth Required: Yes
- Permissions: billing:view

**Response**

```json
{
  "plan": "Pro",
  "next_due": "2025-08-01"
}
```

### PATCH /billing

Update billing plan or payment method.

- Auth Required: Yes
- Permissions: billing:manage

**Request**

```json
{
  "plan": "Enterprise"
}
```

**Response**

```json
{
  "plan": "Enterprise"
}
```

**Note:**  
In a production system, payment handling (e.g. card entry, billing address, invoicing) should be delegated to a third-party provider like Stripe. This endpoint serves as a proof of concept for managing plan changes and simulating billing updates without actual payment processing.