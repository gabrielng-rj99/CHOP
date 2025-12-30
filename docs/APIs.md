# Client Hub Open Project - API Documentation

Base URL: `/` (Most endpoints use the `/api` prefix)

## Authentication

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | Public | `username`, `password` | `token`, `refresh_token`, `user`, `role` |
| `POST` | `/api/refresh-token` | Public | `refresh_token` | `token` |

## Users

*System user management.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/users` | Admin / Root | N/A | List of users (`id`, `username`, `role`, `display_name`) |
| `POST` | `/api/users` | Admin / Root | `username`, `display_name`, `password`, `role` (user/admin/root) | `id`, `username` |
| `GET` | `/api/users/{username}` | Admin / Root | N/A | Complete User Object |
| `PUT` | `/api/users/{username}` | Admin / Root (or Self) | `display_name`, `password` (Optional: `username`, `role` Root only) | `message` |
| `DELETE` | `/api/users/{username}` | Root Only | N/A | `message` |
| `PUT` | `/api/users/{username}/block` | Admin / Root | N/A | `message` |
| `PUT` | `/api/users/{username}/unlock` | Admin / Root | N/A | `message` |

## Clients

*Client/Company registration management.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/clients` | Authenticated | Optional Query: `include_stats=true` | List of Clients (`id`, `name`, `registration_id`, `email`, `status`) |
| `POST` | `/api/clients` | Authenticated | `name`, `registration_id`, `email*`, `address*`, `phone*` (*=Recommended) | `id`, `message` |
| `GET` | `/api/clients/{id}` | Authenticated | N/A | Complete Client Object (includes `affiliates`) |
| `PUT` | `/api/clients/{id}` | Authenticated | `name`, `registration_id`, `email`, `address`, `notes`, `tags` | `message` |
| `DELETE` | `/api/clients/{id}` | Authenticated | N/A | `message` |
| `PUT` | `/api/clients/{id}/archive` | Authenticated | N/A | `message` |
| `PUT` | `/api/clients/{id}/unarchive` | Authenticated | N/A | `message` |
| `GET` | `/api/clients/{id}/affiliates` | Authenticated | N/A | List of Affiliates |
| `POST` | `/api/clients/{id}/affiliates` | Authenticated | `name`, `description`, `email`, `type/tags` | `id`, `name` |

## Affiliates

*Branches, departments, or affiliates linked to a Client.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `PUT` | `/api/affiliates/{id}` | Authenticated | `name`, `description`, `email`, `tags`, `contact_preference` | `id`, `name` |
| `DELETE` | `/api/affiliates/{id}` | Authenticated | N/A | `message` |

## Contracts (Formerly Agreements)

*Contracts or agreements signed with Clients.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/contracts` | Authenticated | N/A | List of Contracts (`id`, `model`, `status`, `value`) |
| `POST` | `/api/contracts` | Authenticated | `client_id`, `subcategory_id`, `model` (name), `start_date`, `value`, `item_key` | `id`, `message` |
| `GET` | `/api/contracts/{id}` | Authenticated | N/A | Contract Object (Detailed `client`, `subcategory`) |
| `PUT` | `/api/contracts/{id}` | Authenticated | `model`, `value`, `start_date`, `end_date`, `status` | `message` |
| `PUT` | `/api/contracts/{id}/archive` | Authenticated | N/A | `message` |

## Categories & Subcategories

*Classification of services or products.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/categories` | Authenticated | N/A | List of Categories |
| `POST` | `/api/categories` | Authenticated | `name` | `id`, `name` |
| `PUT` | `/api/categories/{id}` | Authenticated | `name` | `id`, `name` |
| `DELETE` | `/api/categories/{id}` | Authenticated | N/A | `message` |
| `GET` | `/api/categories/{id}/subcategories` | Authenticated | N/A | List of Subcategories |
| `GET` | `/api/subcategories` | Authenticated | N/A | List of Subcategories |
| `POST` | `/api/subcategories` | Authenticated | `name`, `category_id` | `id`, `name` |
| `PUT` | `/api/subcategories/{id}` | Authenticated | `name` | `id`, `name` |

## Roles & Permissions

*Granular access control (RBAC).*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/roles` | Admin / Root | N/A | List of Roles with Permissions |
| `POST` | `/api/roles` | Root Only | `name` (slug), `display_name`, `priority` | `id`, `name` |
| `PUT` | `/api/roles/{id}` | Root Only | `display_name`, `priority` | `id`, `display_name` |
| `GET` | `/api/roles/{id}/permissions` | Admin / Root | N/A | List of Permissions for Role |
| `PUT` | `/api/roles/{id}/permissions` | Admin / Root | `permission_ids` (Array of UUIDs) | `message` |
| `GET` | `/api/permissions` | Admin / Root | N/A | List of All Available Permissions |
| `GET` | `/api/user/permissions` | Authenticated | N/A | Map of current user's permissions |

## Settings & System

*Global and security configurations.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/settings` | Authenticated | N/A | `branding.app_name`, `branding.logo`, etc. |
| `PUT` | `/api/settings` | Root Only | `settings` (key-value map) | `message` |
| `GET` | `/api/settings/security` | Root Only | N/A | `password_policy`, `lock_level`, etc. |
| `PUT` | `/api/settings/security` | Root Only | `password_min_length`, `lock_level_attempts`... | `message` |
| `GET` | `/api/settings/password-policy` | Authenticated | N/A | `min_length`, `require_special_char`, etc. |
| `GET` | `/api/system-config/dashboard` | Admin / Root | N/A | Dashboard Configs (Widgets) |
| `PUT` | `/api/system-config/dashboard` | Admin / Root | `show_birthdays`, `show_stats` | `message` |
| `PUT` | `/api/settings/global-theme` | Root Only | `theme_preset`, `primary_color` | `message` |

## User Preferences & Themes

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/user/theme` | Authenticated | N/A | `theme_mode`, `primary_color` |
| `PUT` | `/api/user/theme` | Authenticated | `theme_mode` (light/dark), `high_contrast` | `message` |

## Audit Logs

*Security and operation logs.*

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/audit-logs` | Root Only | Query: `limit`, `offset`, `client_type` | List of Logs (`operation`, `user`, `timestamp`) |
| `GET` | `/api/audit-logs/{id}` | Root Only | N/A | Detail (`old_value`, `new_value`) |
| `GET` | `/api/audit-logs/export` | Root Only | N/A | JSON file for download |

## Utilities & Initialization

| Method | Endpoint | Authentication | Required Parameters | Response Fields |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | N/A | `status` |
| `POST` | `/api/upload` | Root Only | Form-Data: `file` | `url` |
| `POST` | `/api/deploy/config` | Deploy Token | `server_port`, `db_host`, `jwt_secret` | `success`, `message` |
| `GET` | `/api/initialize/status` | Public | N/A | `is_initialized`, `database_empty` |
| `POST` | `/api/initialize/admin` | Public (Empty DB) | `username`, `password` | `success`, `admin_id` |
