# Client Hub Open Project - API Documentation

Base URL: `/` (Most endpoints use the `/api` prefix)

---

## Authentication

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | Public | `username`, `password` | `token`, `refresh_token`, `user_id`, `username`, `role`, `display_name` |
| `POST` | `/api/refresh-token` | Public | `refresh_token` | `token` |

---

## Users

*System user management.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/users` | Admin / Root | N/A | List of users (`id`, `username`, `role`, `display_name`, `failed_attempts`, `lock_level`, `locked_until`) |
| `POST` | `/api/users` | Admin / Root | `username`, `display_name`, `password`, `role` (user/admin/root) | `id`, `message` |
| `GET` | `/api/users/{username}` | Admin / Root | N/A | Complete User Object |
| `PUT` | `/api/users/{username}` | Admin / Root (or Self) | `display_name`, `password` (Optional: `username`, `role` - Root only) | `message` |
| `PUT` | `/api/users/{username}/block` | Admin / Root | N/A | `message` |
| `PUT` | `/api/users/{username}/unlock` | Admin / Root | N/A | `message` |

**Security Rules:**
- Only `root` can create other `root` users
- Only `root` can change `username` or `role`
- Only `root` can change passwords of other users
- `admin` cannot change data of other `admin` or `root` users

---

## Clients

*Client/Company registration management.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/clients` | Authenticated | Optional Query: `include_stats=true` | List of Clients (`id`, `name`, `registration_id`, `nickname`, `birth_date`, `email`, `phone`, `address`, `notes`, `status`, `tags`, `contact_preference`, `last_contact_date`, `next_action_date`, `created_at`, `documents`, `archived_at`) + optional stats |
| `POST` | `/api/clients` | Authenticated | `name` (Required), `registration_id`*, `nickname`*, `birth_date`*, `email`*, `phone`*, `address`*, `notes`*, `tags`*, `contact_preference`*, `documents`* (*=Optional) | `id`, `message` |
| `GET` | `/api/clients/{id}` | Authenticated | N/A | Complete Client Object |
| `PUT` | `/api/clients/{id}` | Authenticated | `name`, `registration_id`, `nickname`, `email`, `phone`, `address`, `notes`, `tags`, `contact_preference`, `documents` | `message` |
| `DELETE` | `/api/clients/{id}` | Authenticated | N/A | 204 No Content |
| `PUT` | `/api/clients/{id}/archive` | Authenticated | N/A | `message` |
| `PUT` | `/api/clients/{id}/unarchive` | Authenticated | N/A | `message` |
| `GET` | `/api/clients/{id}/affiliates` | Authenticated | N/A | List of Affiliates |
| `POST` | `/api/clients/{id}/affiliates` | Authenticated | `name` (Required), `description`*, `birth_date`*, `email`*, `phone`*, `address`*, `notes`*, `tags`*, `contact_preference`*, `documents`* | `id`, `message` |

**With `include_stats=true`:** Response includes `active_contracts`, `expired_contracts`, `archived_contracts` per client.

---

## Affiliates

*Branches, departments, or affiliates linked to a Client.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `PUT` | `/api/affiliates/{id}` | Authenticated | `name`, `description`, `birth_date`, `email`, `phone`, `address`, `notes`, `tags`, `contact_preference`, `documents` | `message` |
| `DELETE` | `/api/affiliates/{id}` | Authenticated | N/A | `message` |

---

## Contracts

*Contracts signed with Clients.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/contracts` | Authenticated | N/A | List of Contracts (`id`, `model`, `item_key`, `start_date`, `end_date`, `subcategory_id`, `client_id`, `affiliate_id`, `archived_at`) |
| `POST` | `/api/contracts` | Authenticated | `client_id`, `subcategory_id`, `model`, `item_key` (Optional: `start_date`, `end_date`, `affiliate_id`) | `id`, `message` |
| `GET` | `/api/contracts/{id}` | Authenticated | N/A | Complete Contract Object |
| `PUT` | `/api/contracts/{id}` | Authenticated | `model`, `item_key`, `start_date`, `end_date`, `subcategory_id`, `client_id`, `affiliate_id` | `message` |
| `PUT` | `/api/contracts/{id}/archive` | Authenticated | N/A | `message` |

**Contract Status Logic:**
- `start_date = null`: Contract always started (infinite lower bound)
- `end_date = null`: Contract never expires (infinite upper bound)
- Calculated Status: `Ativo`, `Expirando em Breve` (≤30 days to end), `Expirado`

---

## Categories

*Classification of services or products.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/categories` | Authenticated | Optional Query: `include_archived=true` | List of Categories (`id`, `name`, `status`, `archived_at`) |
| `POST` | `/api/categories` | Authenticated | `name` | `id`, `message` |
| `GET` | `/api/categories/{id}` | Authenticated | N/A | Category Object |
| `PUT` | `/api/categories/{id}` | Authenticated | `name` | `message` |
| `DELETE` | `/api/categories/{id}` | Authenticated | N/A | `message` |
| `POST` | `/api/categories/{id}/archive` | Authenticated | N/A | `message` |
| `POST` | `/api/categories/{id}/unarchive` | Authenticated | N/A | `message` |
| `GET` | `/api/categories/{id}/subcategories` | Authenticated | Optional Query: `include_archived=true` | List of Subcategories |

---

## Subcategories

*Subcategories/Lines within Categories.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/subcategories` | Authenticated | N/A | List of Subcategories (`id`, `name`, `category_id`, `archived_at`) |
| `POST` | `/api/subcategories` | Authenticated | `name`, `category_id` | `id`, `message` |
| `GET` | `/api/subcategories/{id}` | Authenticated | N/A | Subcategory Object |
| `PUT` | `/api/subcategories/{id}` | Authenticated | `name` | `message` |
| `DELETE` | `/api/subcategories/{id}` | Authenticated | N/A | `message` |
| `POST` | `/api/subcategories/{id}/archive` | Authenticated | N/A | `message` |
| `POST` | `/api/subcategories/{id}/unarchive` | Authenticated | N/A | `message` |

---

## Roles & Permissions

*Granular access control (RBAC).*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/roles` | Admin+ (with `roles:read`) | Optional Query: `include_permissions=true` | List of Roles (`id`, `name`, `display_name`, `description`, `is_system`, `is_active`, `priority`) |
| `POST` | `/api/roles` | Root Only | `name` (slug), `display_name`, `priority` (Optional: `description`) | `id`, `name` |
| `GET` | `/api/roles/{id}` | Admin+ (with `roles:read`) | Optional Query: `include_permissions=true` | Role Object (optionally with Permissions) |
| `PUT` | `/api/roles/{id}` | Root Only | `display_name`, `priority` (Optional: `description`) | `id`, `display_name` |
| `DELETE` | `/api/roles/{id}` | Root Only | N/A | `message` |
| `GET` | `/api/roles/{id}/permissions` | Admin+ (with `roles:read`) | N/A | List of Permissions for Role |
| `PUT` | `/api/roles/{id}/permissions` | Admin+ (with `roles:update`) | `permission_ids` (Array of UUIDs) | `message` |
| `GET` | `/api/permissions` | Admin+ (with `roles:read`) | N/A | List of All Available Permissions (`id`, `resource`, `action`, `display_name`, `description`, `category`) |
| `GET` | `/api/user/permissions` | Authenticated | N/A | `user_id`, `role`, `role_id`, `permissions[]`, `resources{}` |
| `GET` | `/api/user/check-permission` | Authenticated | Query: `resource`, `action` | `has_permission` (boolean) |

---

## Role Session Policies

*Session duration and security settings per role.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/roles/session-policies` | Root Only | N/A | List of Role Session Policies |
| `GET` | `/api/roles/{id}/session-policy` | Root Only | N/A | `id`, `role_id`, `role_name`, `session_duration_minutes`, `refresh_token_duration_minutes`, `max_concurrent_sessions`, `idle_timeout_minutes`, `require_2fa`, `is_active` |
| `PUT` | `/api/roles/{id}/session-policy` | Root Only | `session_duration_minutes` (5-1440), `refresh_token_duration_minutes` (60-525600), `max_concurrent_sessions`*, `idle_timeout_minutes`*, `require_2fa` | Session Policy Object |

---

## Role Password Policies

*Password requirements per role.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/roles/password-policies` | Root Only | N/A | List of Role Password Policies (summary) |
| `GET` | `/api/roles/{id}/password-policy` | Root Only | N/A | `id`, `role_id`, `role_name`, `min_length`, `max_length`, `require_uppercase`, `require_lowercase`, `require_numbers`, `require_special`, `allowed_special_chars`, `max_age_days`, `history_count`, `min_age_hours`, `min_unique_chars`, `no_username_in_password`, `no_common_passwords`, `description`, `is_active` |
| `PUT` | `/api/roles/{id}/password-policy` | Root Only | `min_length`, `max_length`, `require_uppercase`, `require_lowercase`, `require_numbers`, `require_special`, `allowed_special_chars`*, `max_age_days`*, `history_count`*, `min_age_hours`*, `min_unique_chars`*, `no_username_in_password`, `no_common_passwords`, `description`* | Password Policy Object |
| `DELETE` | `/api/roles/{id}/password-policy` | Root Only | N/A | `message` |

---

## Settings & System

*Global settings, branding, and labels.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/settings` | Root Only | N/A | Key-value map: `branding.app_name`, `branding.logo`, `labels.client`, `labels.affiliate`, `labels.category`, `labels.subcategory`, `labels.contract`, etc. |
| `PUT` | `/api/settings` | Root Only | `settings` (key-value map) | `message` |

**Setting Validation:**
- Max 2000 chars per value (1MB for branding images with `branding.` prefix)
- XSS patterns blocked (`<script>`, `javascript:`, etc.)
- Color values must be valid hex (`#RGB` or `#RRGGBB`)

---

## Security Configuration

*Global security and password policy settings.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/settings/security` | Root Only | N/A | `lock_level_1_attempts`, `lock_level_1_duration`, `lock_level_2_attempts`, `lock_level_2_duration`, `lock_level_3_attempts`, `lock_level_3_duration`, `lock_manual_attempts`, `password_min_length`, `password_require_upper`, `password_require_lower`, `password_require_numbers`, `password_require_special`, `session_duration`, `refresh_token_duration`, `rate_limit`, `rate_burst`, `audit_retention_days`, `audit_log_reads`, `notification_email`, `notification_phone` |
| `PUT` | `/api/settings/security` | Root Only | Same fields as GET (all optional) | `message` |
| `GET` | `/api/settings/password-policy` | Authenticated | N/A | `min_length`, `require_upper`, `require_lower`, `require_numbers`, `require_special` |

---

## User Theme & Preferences

*User-specific theme and accessibility settings.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/user/theme` | Authenticated | N/A | `theme_preset`, `theme_mode`, `layout_mode`, `primary_color`, `secondary_color`, `background_color`, `surface_color`, `text_color`, `text_secondary_color`, `border_color`, `high_contrast`, `color_blind_mode`, `dyslexic_font`, `font_general`, `font_title`, `font_table_title` |
| `PUT` | `/api/user/theme` | Authenticated (if permitted) | `theme_mode` (light/dark/system), `layout_mode` (standard/full/centralized), `theme_preset`*, `primary_color`*, `secondary_color`*, `background_color`*, `surface_color`*, `text_color`*, `text_secondary_color`*, `border_color`*, `high_contrast`*, `color_blind_mode` (none/protanopia/deuteranopia/tritanopia), `dyslexic_font`*, `font_general`*, `font_title`*, `font_table_title`* | User Theme Object |
| `GET` | `/api/settings/theme-permissions` | Root Only | N/A | `users_can_edit_theme`, `admins_can_edit_theme` |
| `PUT` | `/api/settings/theme-permissions` | Root Only | `users_can_edit_theme`, `admins_can_edit_theme` | `message` |
| `GET` | `/api/settings/global-theme` | Root Only | N/A | Global theme defaults (same fields as user theme) |
| `PUT` | `/api/settings/global-theme` | Root Only | `theme_preset`*, `primary_color`*, `secondary_color`*, `background_color`*, `surface_color`*, `text_color`*, `text_secondary_color`*, `border_color`*, `font_general`*, `font_title`*, `font_table_title`* | Global Theme Object |
| `GET` | `/api/settings/allowed-themes` | Authenticated | N/A | `allowed_themes` (array of theme preset names) |
| `PUT` | `/api/settings/allowed-themes` | Root Only | `allowed_themes` (array of strings) | `message` |
| `GET` | `/api/settings/system-config` | Root Only | N/A | `login_block_time`, `login_attempts`, `notification_email`, `notification_phone` |
| `PUT` | `/api/settings/system-config` | Root Only | `login_block_time`*, `login_attempts`*, `notification_email`*, `notification_phone`* | `message` |

---

## Dashboard Configuration

*Dashboard display settings.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/system-config/dashboard` | Admin / Root | N/A | `show_birthdays`, `birthdays_days_ahead`, `show_recent_activity`, `recent_activity_count`, `show_statistics`, `show_expiring_contracts`, `expiring_days_ahead`, `show_quick_actions` |
| `PUT` | `/api/system-config/dashboard` | Admin / Root | `show_birthdays`, `birthdays_days_ahead` (1-90), `show_recent_activity`, `recent_activity_count` (5-50), `show_statistics`, `show_expiring_contracts`, `expiring_days_ahead` (7-180), `show_quick_actions` | `success`, `message` |

---

## Audit Logs

*Security and operation logs.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/audit-logs` | Root Only | Query (all optional): `resource`, `operation`, `admin_id`, `admin_search`, `resource_id`, `resource_search`, `changed_data`, `status`, `ip_address`, `start_date` (RFC3339), `end_date` (RFC3339), `limit` (max 1000), `offset` | `data[]` (audit logs), `total`, `limit`, `offset` |
| `GET` | `/api/audit-logs/{id}` | Root Only | N/A | `id`, `timestamp`, `operation`, `resource`, `resource_id`, `admin_id`, `admin_username`, `old_value`, `new_value`, `status`, `error_message`, `ip_address`, `user_agent`, `request_method`, `request_path`, `request_id`, `response_code`, `execution_time_ms` |
| `GET` | `/api/audit-logs/resource/{resource}/{resourceID}` | Root Only | Query: `limit`*, `offset`* | `data[]`, `resource`, `resource_id`, `limit`, `offset` |
| `GET` | `/api/audit-logs/export` | Root Only | Query (all optional): `resource`, `operation`, `admin_id`, `admin_search`, `resource_search`, `changed_data` | JSON file download (max 10000 records) |

**Operations:** `create`, `update`, `delete`, `login`, `archive`, `unarchive`, `upload`  
**Resources:** `user`, `client`, `affiliate`, `contract`, `category`, `subcategory`, `auth`, `settings_branding`, `settings_labels`, `settings_system`, `role_session_policy`, `role_password_policy`, `dashboard_config`, `file`  
**Status:** `success`, `error`, `failed`

---

## File Upload

*File upload for images.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/upload` | Root Only | Form-Data: `file` (max 15MB) | `url` |

**Allowed MIME types:** `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/svg+xml`

**Static Files:** Uploaded files served at `/uploads/{filename}`

---

## Deploy Configuration

*Runtime configuration for deployment.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/deploy/config` | Deploy Token (Bearer) | `server_host`*, `server_port`*, `database_host`*, `database_port`*, `database_name`*, `database_user`*, `database_password`*, `database_ssl_mode`*, `jwt_secret_key`*, `jwt_expiration_time`*, `jwt_refresh_expiration_time`*, `security_password_min_length`*, `security_password_require_uppercase`*, `security_password_require_lowercase`*, `security_password_require_numbers`*, `security_password_require_special`*, `security_max_failed_attempts`*, `security_lockout_duration_minutes`*, `app_env`* | `success`, `message`, `errors[]`, `config{}` |
| `GET` | `/api/deploy/config/defaults` | Public | N/A | `success`, `config{}` (server, database, jwt settings) |
| `GET` | `/api/deploy/status` | Public | N/A | `status`, `message`, `environment`, `version`, `config_loaded`, `timestamp` |
| `POST` | `/api/deploy/validate` | Public | Same as `/api/deploy/config` | `success`, `message`, `errors[]` |

**Deploy Token:** Set via `DEPLOY_TOKEN` environment variable. Send as `Authorization: Bearer <token>`.

---

## System Initialization

*Initial system setup when database is empty.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/initialize/status` | Public | N/A | `is_initialized`, `has_database`, `database_empty`, `requires_setup`, `message`, `database_status` (empty/has_data/connected/error), `tables_with_data[]` |
| `POST` | `/api/initialize/admin` | Public (Empty DB Only) | `display_name`, `password` (min 24 chars), `username`* (defaults to "root") | `success`, `message`, `admin_id`, `admin_username` |

**⚠️ SECURITY:** `/api/initialize/admin` is ONLY accessible when the database is COMPLETELY EMPTY. Once any data exists, this endpoint returns 403 Forbidden.

---

## Health Check

*System health monitoring.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | N/A | `status` (healthy/unhealthy), `message`*, `timestamp` |

---

## Common Response Formats

### Success Response
```json
{
  "message": "Operation successful",
  "data": { ... }
}
```

### Error Response
```json
{
  "error": "Error message description"
}
```

### HTTP Status Codes

| Code | Description |
| :--- | :--- |
| `200` | Success |
| `201` | Created |
| `204` | No Content (Delete success) |
| `400` | Bad Request (Validation error) |
| `401` | Unauthorized (Missing/Invalid token) |
| `403` | Forbidden (Insufficient permissions) |
| `404` | Not Found |
| `405` | Method Not Allowed |
| `500` | Internal Server Error |
| `503` | Service Unavailable |

---

## Authentication Header

For authenticated endpoints, include the JWT token:

```
Authorization: Bearer <jwt_token>
```

---

## Rate Limiting

- Default: 100 requests per minute
- Burst: 20 requests

Response headers:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## Security Features

- **CORS:** Enabled for configured origins
- **Security Headers:** `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, `Content-Security-Policy`
- **Request Logging:** All requests are logged with user info, IP, and execution time
- **Audit Trail:** All data modifications are logged to audit_logs table
