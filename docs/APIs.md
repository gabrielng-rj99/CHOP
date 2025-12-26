# Project API Documentation

This document outlines the API endpoints available in the Entity Hub Open Project backend.

## Base URL
All API endpoints are prefixed with `/api`.

## Authentication
Most endpoints require a JSON Web Token (JWT) in the `Authorization` header:
`Authorization: Bearer <token>`

## 1. Authentication

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | Authenticate user and receive access/refresh tokens. | No |
| `POST` | `/api/refresh-token` | Refresh an expired access token using a refresh token. | No |

## 2. Users (Admin/Root Only)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/users` | List all users. |
| `POST` | `/api/users` | Create a new user. |
| `GET` | `/api/users/{username}` | Get details of a specific user. |
| `PUT` | `/api/users/{username}` | Update a user's details. |
| `DELETE` | `/api/users/{username}` | Delete a user. |
| `PUT` | `/api/users/{username}/block` | Block a user account. |
| `PUT` | `/api/users/{username}/unlock` | Unlock a user account. |

## 3. Entities (Clients)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/entities` | List all entities. Query params: `include_stats=true`. |
| `POST` | `/api/entities` | Create a new entity. |
| `GET` | `/api/entities/{id}` | Get details of a specific entity. |
| `PUT` | `/api/entities/{id}` | Update an entity. |
| `PUT` | `/api/entities/{id}/archive` | Archive an entity. |
| `PUT` | `/api/entities/{id}/unarchive` | Unarchive an entity. |
| `GET` | `/api/entities/{id}/sub_entities` | List sub-entities (dependents) for an entity. |
| `POST` | `/api/entities/{id}/sub_entities` | Create a sub-entity for an entity. |

## 4. Sub-Entities (Dependents)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/sub-entities/{id}` | Get details of a sub-entity. |
| `PUT` | `/api/sub-entities/{id}` | Update a sub-entity. |
| `DELETE` | `/api/sub-entities/{id}` | Delete a sub-entity. |

## 5. Agreements (Contracts)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/agreements` | List all agreements. |
| `POST` | `/api/agreements` | Create a new agreement. |
| `GET` | `/api/agreements/{id}` | Get details of an agreement. |
| `PUT` | `/api/agreements/{id}` | Update an agreement. |
| `PUT` | `/api/agreements/{id}/archive` | Archive an agreement. |
| `PUT` | `/api/agreements/{id}/unarchive` | Unarchive an agreement. |

## 6. Categories

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/categories` | List all categories. Query params: `include_archived=true`. |
| `POST` | `/api/categories` | Create a new category. |
| `GET` | `/api/categories/{id}` | Get details of a category. |
| `PUT` | `/api/categories/{id}` | Update a category. |
| `DELETE` | `/api/categories/{id}` | Delete a category (soft delete/archive usually preferred). |
| `POST` | `/api/categories/{id}/archive` | Archive a category. |
| `POST` | `/api/categories/{id}/unarchive` | Unarchive a category. |
| `GET` | `/api/categories/{id}/subcategories` | List subcategories (lines) for a category. |

## 7. Subcategories (Lines)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/subcategories` | Create a new subcategory. |
| `GET` | `/api/subcategories/{id}` | Get details of a subcategory. |
| `PUT` | `/api/subcategories/{id}` | Update a subcategory. |
| `DELETE` | `/api/subcategories/{id}` | Delete a subcategory. |
| `POST` | `/api/subcategories/{id}/archive` | Archive a subcategory. |
| `POST` | `/api/subcategories/{id}/unarchive` | Unarchive a subcategory. |

## 8. Audit Logs (Root Only)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/audit-logs` | List audit logs with filtering. |
| `GET` | `/api/audit-logs/{id}` | Get details of a specific log entry. |
| `GET` | `/api/audit-logs/entity/{type}/{id}` | Get logs for a specific entity. |
| `GET` | `/api/audit-logs/export` | Export logs (JSON/CSV). |

## 9. System Settings (Root Only)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/settings` | Get system settings (Public/Auth depending on config). |
| `PUT` | `/api/settings` | Update system settings. |
| `POST` | `/api/upload` | Upload a file (e.g., logo). |

## 10. Deployment & Config

These endpoints are used for dynamic server configuration.

| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Health check. | Public |
| `GET` | `/api/deploy/status` | Current deployment status. | Public |
| `GET` | `/api/deploy/config/defaults` | Default configuration values. | Public |
| `POST` | `/api/deploy/validate` | Validate a configuration payload. | Public |
| `POST` | `/api/deploy/config` | Update configuration. | **Deploy Token** |
| `POST` | `/api/initialize/admin` | Create the first admin user (only if DB is empty). | Public |
| `GET` | `/api/initialize/status` | Check if initialization is required. | Public |
