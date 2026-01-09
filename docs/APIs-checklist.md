# Client Hub Open Project - API Security Test Checklist

> **Última Atualização:** 2026-01-08
> **Status Geral:** 🔄 Em Progresso

---

## Legenda de Status

 | Símbolo | Significado |
 | --------- | ------------- |
 | ✅ | Teste implementado e passando |
 | ❌ | Teste implementado mas falhando |
 | ⬜ | Teste não implementado |
 | 🔄 | Em progresso |
 | ⚠️ | Teste com issues conhecidos |

---

## Categorias de Testes de Segurança

Para cada endpoint, os seguintes testes devem ser aplicados:

### 1. Validação de Input

- [ ] Empty Request (body vazio)
- [ ] Null Values (campos null)
- [ ] Invalid Types (tipos incorretos)
- [ ] Malformed JSON
- [ ] Missing Required Fields
- [ ] Extra Unknown Fields

### 2. Ataques de Injeção

- [ ] SQL Injection (payloads diversos)
- [ ] XSS (Cross-Site Scripting)
- [ ] Command Injection
- [ ] LDAP Injection
- [ ] XML/XXE Injection

### 3. Overflow e DoS

- [ ] Very Long Strings (10K+ chars)
- [ ] Unicode Overflow
- [ ] Regex DoS (ReDoS)
- [ ] Large Payload (1MB+)
- [ ] Deep Nesting JSON

### 4. Bypass Attempts

- [ ] Case Sensitivity Bypass
- [ ] Encoding Bypass (URL, Base64, Hex)
- [ ] Null Byte Injection
- [ ] Path Traversal
- [ ] Unicode Normalization

### 5. Autenticação e Autorização

- [ ] Without Token (401)
- [ ] Invalid Token (401)
- [ ] Expired Token (401)
- [ ] Wrong Permission (403)
- [ ] Privilege Escalation

### 6. Rate Limiting

- [ ] Burst Requests
- [ ] Slow Rate Limit Bypass

---

## 📋 Authentication APIs

### POST /api/login

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **Empty Request** | Sem body | ✅ | test_input_validation.py |
 | **Null Values** | Username null | ✅ | test_input_validation.py |
 | **Null Values** | Password null | ✅ | test_input_validation.py |
 | **Invalid Types** | Username como array | ✅ | test_input_validation.py |
 | **Invalid Types** | Password como objeto | ✅ | test_input_validation.py |
 | **Malformed JSON** | JSON inválido | ✅ | test_input_validation.py |
 | **SQL Injection** | Username com SQL | ✅ | test_sql_injection.py |
 | **SQL Injection** | Password com SQL | ✅ | test_sql_injection.py |
 | **SQL Injection** | UNION-based | ✅ | test_sql_injection.py |
 | **SQL Injection** | Time-based blind | ✅ | test_sql_injection.py |
 | **SQL Injection** | Boolean-based blind | ✅ | test_sql_injection.py |
 | **SQL Injection** | Stacked queries | ✅ | test_sql_injection.py |
 | **SQL Injection** | Encoded payloads | ✅ | test_sql_injection.py |
 | **SQL Injection** | Comments bypass | ✅ | test_sql_injection.py |
 | **XSS** | Username com script | ✅ | test_xss_security.py |
 | **XSS** | Error messages reflection | ✅ | test_xss_security.py |
 | **Overflow** | Username 10K+ chars | ✅ | test_overflow_dos.py |
 | **Overflow** | Password 10K+ chars | ✅ | test_overflow_dos.py |
 | **Bypass** | Case sensitivity | ✅ | test_bypass_attacks.py |
 | **Bypass** | URL encoded | ✅ | test_bypass_attacks.py |
 | **Brute Force** | Login blocking | ✅ | test_login_blocking.py |
 | **Data Leakage** | Error no sensitive data | ✅ | test_data_leakage.py |

### POST /api/refresh-token

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **JWT Security** | Token inválido | ✅ | test_jwt_security.py |
 | **JWT Security** | Token expirado | ✅ | test_jwt_security.py |
 | **JWT Security** | Token manipulado | ✅ | test_jwt_security.py |
 | **JWT Security** | Algorithm none | ✅ | test_jwt_security.py |
 | **JWT Security** | Refresh como access | ✅ | test_jwt_security.py |
 | **Overflow** | Token 10K+ chars | ⬜ | - |
 | **SQL Injection** | Token com SQL | ⬜ | - |

---

## 📋 Users APIs

### GET /api/users

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_api_endpoints.py |
 | **Auth** | Token inválido | ✅ | test_jwt_security.py |
 | **Permission** | Como root | ✅ | test_api_endpoints.py |
 | **Permission** | Como admin | ✅ | test_api_endpoints.py |
 | **Permission** | Como user (denied) | ✅ | test_api_endpoints.py |
 | **Data Leakage** | Sem password hash | ✅ | test_data_leakage.py |
 | **Data Leakage** | Sem auth_secret | ✅ | test_data_leakage.py |

### POST /api/users

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **Null Values** | Campos null | ✅ | test_input_validation.py |
 | **Invalid Types** | Role como número | ✅ | test_input_validation.py |
 | **Invalid Types** | Role como array | ✅ | test_input_validation.py |
 | **Permission** | Como root | ✅ | test_api_endpoints.py |
 | **Permission** | Como admin | ✅ | test_api_endpoints.py |
 | **Permission** | Como user (denied) | ✅ | test_api_endpoints.py |
 | **Permission** | Admin criando root | ✅ | test_api_endpoints.py |
 | **SQL Injection** | Username com SQL | ✅ | test_sql_injection.py |
 | **XSS** | Username com script | ✅ | test_xss_security.py |
 | **XSS** | Display name com script | ✅ | test_xss_security.py |
 | **Overflow** | Username 10K+ chars | ⬜ | - |
 | **Overflow** | Password 10K+ chars | ⬜ | - |
 | **Bypass** | Role case sensitivity | ✅ | test_authorization.py |
 | **Bypass** | Role vazio | ✅ | test_authorization.py |
 | **Bypass** | Role inválido | ✅ | test_authorization.py |
 | **Password** | Validação de força | ✅ | test_password_validation.py |

### GET /api/users/{username}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Acesso próprio | ⬜ | - |
 | **Permission** | Acesso a outros | ✅ | test_authorization.py |
 | **Data Leakage** | Sem password hash | ✅ | test_data_leakage.py |
 | **Path Traversal** | Username com ../ | ⬜ | - |
 | **SQL Injection** | Username com SQL | ⬜ | - |
 | **Overflow** | Username 10K+ chars | ⬜ | - |

### PUT /api/users/{username}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Atualizar próprio | ⬜ | - |
 | **Permission** | Atualizar outros | ✅ | test_authorization.py |
 | **Escalation** | Elevar privilégios | ✅ | test_authorization.py |
 | **XSS** | Display name com script | ⬜ | - |
 | **SQL Injection** | Display name com SQL | ⬜ | - |
 | **Overflow** | Display name 10K+ chars | ⬜ | - |

### PUT /api/users/{username}/block

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |
 | **Self Block** | Bloquear próprio | ⬜ | - |

### PUT /api/users/{username}/unlock

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |

---

## 📋 Clients APIs

### GET /api/clients

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_api_endpoints.py |
 | **Permission** | Com permissão | ✅ | test_api_endpoints.py |
 | **Query Params** | include_stats SQL | ⬜ | - |
 | **Query Params** | XSS em params | ✅ | test_xss_security.py |
 | **SQL Injection** | Search params | ✅ | test_sql_injection.py |

### POST /api/clients

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **Null Values** | Name null | ✅ | test_input_validation.py |
 | **Permission** | Sem permissão | ⬜ | - |
 | **SQL Injection** | Name com SQL | ✅ | test_sql_injection.py |
 | **XSS** | Name com script | ✅ | test_xss_security.py |
 | **XSS** | Notes com script | ✅ | test_xss_security.py |
 | **XSS** | Email com script | ✅ | test_xss_security.py |
 | **XSS** | Address com script | ✅ | test_xss_security.py |
 | **Overflow** | Name 10K+ chars | ⬜ | - |
 | **Overflow** | Notes 10K+ chars | ⬜ | - |

### GET /api/clients/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Not Found** | ID inexistente | ✅ | test_api_endpoints.py |
 | **SQL Injection** | ID com SQL | ⬜ | - |
 | **Invalid ID** | ID não-UUID | ⬜ | - |

### PUT /api/clients/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Not Found** | ID inexistente | ⬜ | - |
 | **XSS** | Todos os campos | ⬜ | - |
 | **SQL Injection** | Todos os campos | ⬜ | - |
 | **Overflow** | Todos os campos | ⬜ | - |

### DELETE /api/clients/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |
 | **Not Found** | ID inexistente | ✅ | test_api_endpoints.py |
 | **SQL Injection** | ID com SQL | ⬜ | - |

### PUT /api/clients/{id}/archive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |
 | **Already Archived** | Arquivar arquivado | ⬜ | - |

### PUT /api/clients/{id}/unarchive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |
 | **Not Archived** | Desarquivar ativo | ⬜ | - |

### GET /api/clients/{id}/affiliates

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Not Found** | ID inexistente | ⬜ | - |

### POST /api/clients/{id}/affiliates

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ⬜ | - |
 | **Null Values** | Name null | ⬜ | - |
 | **XSS** | Todos os campos | ⬜ | - |
 | **SQL Injection** | Todos os campos | ⬜ | - |
 | **Overflow** | Todos os campos | ⬜ | - |

---

## 📋 Affiliates APIs

### PUT /api/affiliates/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **Permission** | Sem permissão | ✅ | test_upload_deploy_health.py |
 | **Not Found** | ID inexistente | ✅ | test_upload_deploy_health.py |
 | **XSS** | Todos os campos | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | Todos os campos | ✅ | test_upload_deploy_health.py |
 | **Overflow** | Todos os campos | ⬜ | - |

### DELETE /api/affiliates/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **Permission** | Sem permissão | ✅ | test_upload_deploy_health.py |
 | **Not Found** | ID inexistente | ✅ | test_upload_deploy_health.py |

---

## 📋 Contracts APIs

### GET /api/contracts

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |
 | **SQL Injection** | Search params | ✅ | test_sql_injection.py |

### POST /api/contracts

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **XSS** | Model com script | ✅ | test_xss_security.py |
 | **SQL Injection** | Todos os campos | ⬜ | - |
 | **Overflow** | Todos os campos | ⬜ | - |

### GET /api/contracts/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Not Found** | ID inexistente | ⬜ | - |

### PUT /api/contracts/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Todos os campos | ⬜ | - |
 | **SQL Injection** | Todos os campos | ⬜ | - |
 | **Overflow** | Todos os campos | ⬜ | - |

### PUT /api/contracts/{id}/archive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |

---

## 📋 Categories APIs

### GET /api/categories

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Query Params** | include_archived SQL | ⬜ | - |

### POST /api/categories

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ✅ | test_input_validation.py |
 | **XSS** | Name com script | ✅ | test_xss_security.py |
 | **SQL Injection** | Name com SQL | ✅ | test_sql_injection.py |
 | **Overflow** | Name 10K+ chars | ⬜ | - |

### GET /api/categories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Not Found** | ID inexistente | ⬜ | - |

### PUT /api/categories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Name com script | ⬜ | - |
 | **SQL Injection** | Name com SQL | ⬜ | - |

### DELETE /api/categories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Permission** | Sem permissão | ⬜ | - |

### POST /api/categories/{id}/archive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### POST /api/categories/{id}/unarchive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### GET /api/categories/{id}/subcategories

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

---

## 📋 Subcategories APIs

### GET /api/subcategories

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### POST /api/subcategories

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ⬜ | - |
 | **XSS** | Name com script | ⬜ | - |
 | **SQL Injection** | Name com SQL | ⬜ | - |
 | **Overflow** | Name 10K+ chars | ⬜ | - |

### GET /api/subcategories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/subcategories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Name com script | ⬜ | - |

### DELETE /api/subcategories/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### POST /api/subcategories/{id}/archive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### POST /api/subcategories/{id}/unarchive

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

---

## 📋 Roles & Permissions APIs

### GET /api/roles

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Query Params** | include_permissions SQL | ⬜ | - |

### POST /api/roles

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Empty Request** | Body vazio | ⬜ | - |
 | **XSS** | Name com script | ⬜ | - |
 | **SQL Injection** | Name com SQL | ⬜ | - |

### GET /api/roles/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/roles/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Fields com script | ⬜ | - |

### DELETE /api/roles/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **System Role** | Deletar role sistema | ⬜ | - |

### GET /api/roles/{id}/permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/roles/{id}/permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |
 | **Invalid IDs** | UUIDs inválidos | ✅ | test_roles_permissions_security.py |
 | **Escalation** | Adicionar perms superiores | ✅ | test_roles_permissions_security.py |

### GET /api/permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

### GET /api/user/permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

### GET /api/user/check-permission

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |
 | **SQL Injection** | Query params | ✅ | test_roles_permissions_security.py |

---

## 📋 Role Session Policies APIs

### GET /api/roles/session-policies

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |
 | **Permission** | Sem permissão | ✅ | test_roles_permissions_security.py |

### GET /api/roles/{id}/session-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

### PUT /api/roles/{id}/session-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |
 | **Validation** | Valores fora do range | ✅ | test_roles_permissions_security.py |
 | **Overflow** | Valores extremos | ✅ | test_roles_permissions_security.py |

---

## 📋 Role Password Policies APIs

### GET /api/roles/password-policies

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

### GET /api/roles/{id}/password-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

### PUT /api/roles/{id}/password-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |
 | **Validation** | Valores inválidos | ✅ | test_roles_permissions_security.py |
 | **XSS** | allowed_special_chars | ✅ | test_roles_permissions_security.py |

### DELETE /api/roles/{id}/password-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_roles_permissions_security.py |

---

## 📋 Settings APIs

### GET /api/settings

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_settings_security.py |

### PUT /api/settings

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_settings_security.py |
 | **XSS** | Valores com script | ⬜ | - |
 | **Overflow** | Valores > 2000 chars | ⬜ | - |
 | **Bypass** | XSS patterns | ⬜ | - |

### GET /api/settings/security

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/settings/security

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Validation** | Valores inválidos | ⬜ | - |

### GET /api/settings/password-policy

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

---

## 📋 Theme APIs

### GET /api/user/theme

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/user/theme

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Color values | ✅ | test_appearance_security.py |
 | **Validation** | Invalid colors | ⬜ | - |

### GET /api/settings/theme-permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/settings/theme-permissions

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### GET /api/settings/global-theme

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/settings/global-theme

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Color values | ⬜ | - |

### GET /api/settings/allowed-themes

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/settings/allowed-themes

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **XSS** | Theme names | ⬜ | - |

### GET /api/settings/system-config

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/settings/system-config

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

---

## 📋 Dashboard APIs

### GET /api/system-config/dashboard

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |

### PUT /api/system-config/dashboard

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ⬜ | - |
 | **Validation** | Valores fora do range | ⬜ | - |

---

## 📋 Audit Logs APIs

### GET /api/audit-logs

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **Permission** | Sem permissão | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | Query params | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | ORDER BY | ✅ | test_sql_injection.py |
 | **Overflow** | limit extremo | ✅ | test_upload_deploy_health.py |
 | **Data Leakage** | Sem senhas | ✅ | test_data_leakage.py |

### GET /api/audit-logs/{id}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |

### GET /api/audit-logs/resource/{resource}/{resourceID}

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **Path Traversal** | resource com ../ | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | resource/resourceID | ✅ | test_upload_deploy_health.py |

### GET /api/audit-logs/export

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **Permission** | Sem permissão | ✅ | test_upload_deploy_health.py |

---

## 📋 File Upload APIs

### POST /api/upload

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem token | ✅ | test_upload_deploy_health.py |
 | **File Type** | MIME type inválido | ✅ | test_upload_deploy_health.py |
 | **File Size** | > 15MB | ✅ | test_upload_deploy_health.py |
 | **Malicious File** | SVG com script | ✅ | test_upload_deploy_health.py |
 | **Path Traversal** | Filename com ../ | ✅ | test_upload_deploy_health.py |
 | **Extension** | Double extension | ✅ | test_upload_deploy_health.py |

---

## 📋 Deploy APIs

### POST /api/deploy/config

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Auth** | Sem deploy token | ✅ | test_upload_deploy_health.py |
 | **Auth** | Token inválido | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | Config values | ✅ | test_upload_deploy_health.py |
 | **XSS** | Config values | ✅ | test_upload_deploy_health.py |

### GET /api/deploy/config/defaults

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Security** | Protegido se instalado | ✅ | test_upload_deploy_health.py |
 | **Data Leakage** | Sem secrets | ✅ | test_upload_deploy_health.py |

### GET /api/deploy/status

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Public** | Sem auth funciona | ✅ | test_upload_deploy_health.py |

### POST /api/deploy/validate

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Public** | Sem auth funciona | ✅ | test_upload_deploy_health.py |
 | **SQL Injection** | Config values | ✅ | test_upload_deploy_health.py |

---

## 📋 System Initialization APIs

### GET /api/initialize/status

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Public** | Sem auth funciona | ✅ | test_initialization_security.py |
 | **Data Leakage** | Info disclosure | ✅ | test_initialization_security.py |

### POST /api/initialize/admin

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Security** | DB não vazio (403) | ✅ | test_initialization_security.py |
 | **Empty Request** | Body vazio | ⬜ | - |
 | **Password** | < 24 chars | ⬜ | - |
 | **XSS** | username/display_name | ⬜ | - |
 | **SQL Injection** | Todos os campos | ⬜ | - |

---

## 📋 Health Check APIs

### GET /health

 | Categoria | Teste | Status | Arquivo |
 | ----------- | ------- | -------- | --------- |
 | **Public** | Sem auth funciona | ⬜ | - |
 | **Data Leakage** | Sem info sensível | ⬜ | - |

---

## 📊 Resumo de Cobertura

 | Categoria de API | Total Endpoints | Testes Implementados | Cobertura |
 | ----------------- | ----------------- | --------------------- | ----------- |
 | Authentication | 2 | 25+ | � 90% |
 | Users | 6 | 35+ | � 80% |
 | Clients | 9 | 25+ | 🟡 70% |
 | Affiliates | 2 | 10+ | � 60% |
 | Contracts | 5 | 30+ | � 85% |
 | Categories | 8 | 25+ | � 80% |
 | Subcategories | 7 | 20+ | � 75% |
 | Roles & Permissions | 11 | 30+ | � 80% |
 | Session Policies | 3 | 10+ | � 70% |
 | Password Policies | 4 | 10+ | � 70% |
 | Settings | 5 | 20+ | � 80% |
 | Theme | 10 | 15+ | � 60% |
 | Dashboard | 2 | 10+ | � 80% |
 | Audit Logs | 4 | 15+ | � 80% |
 | File Upload | 1 | 10+ | � 85% |
 | Deploy | 4 | 15+ | � 70% |
 | Initialization | 2 | 10+ | � 80% |
 | Health | 1 | 5+ | � 90% |

**Total Geral:** ~86 endpoints, **531 testes** implementados, ~75% cobertos

---

## 📝 Testes Transversais (Cross-API)

 | Teste | Status | Arquivo |
 | ------- | -------- | --------- |
 | SQL Injection geral | ✅ | test_sql_injection.py |
 | XSS geral | ✅ | test_xss_security.py |
 | JWT Security | ✅ | test_jwt_security.py |
 | Authorization geral | ✅ | test_authorization.py |
 | Data Leakage | ✅ | test_data_leakage.py |
 | Input Validation | ✅ | test_input_validation.py |
 | Password Validation | ✅ | test_password_validation.py |
 | Login Blocking | ✅ | test_login_blocking.py |
 | Initialization Security | ✅ | test_initialization_security.py |
 | Appearance Security | ✅ | test_appearance_security.py |
 | Database Resilience | ✅ | test_database_resilience.py |
 | **Overflow/DoS** | ✅ | test_overflow_dos.py |
 | **Bypass Attacks** | ✅ | test_bypass_attacks.py |
 | **Roles/Permissions Security** | ✅ | test_roles_permissions_security.py |
 | **Settings Security** | ✅ | test_settings_security.py |
 | **Categories/Subcategories** | ✅ | test_categories_subcategories_security.py |
 | **Contracts Security** | ✅ | test_contracts_security.py |
 | **Upload/Deploy/Health** | ✅ | test_upload_deploy_health.py |

---

## 🔒 Referências de Segurança

- OWASP Top 10 2021
- OWASP API Security Top 10
- NIST SP 800-53
- CWE/SANS Top 25
- Cisco Security Best Practices
- SANS Institute Guidelines
