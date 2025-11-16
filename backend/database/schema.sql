-- schema.sql adaptado para PostgreSQL com case-insensitive collation
--
-- ATENÇÃO: Este arquivo foi atualizado para incluir:
-- 1. CITEXT para campos case-insensitive (exceto senhas)
-- 2. Datas opcionais em contratos (start_date e end_date podem ser NULL)
-- 3. Constraint unique para nome de linha por categoria
--
-- Para aplicar estas mudanças em um banco existente, você deve:
-- DROP DATABASE contracts_manager;
-- CREATE DATABASE contracts_manager;
-- E então executar este script novamente.

-- Extensão para case-insensitive (se necessário)
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username CITEXT UNIQUE,
    display_name VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    role VARCHAR(50),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_level INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    auth_secret VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    registration_id CITEXT,
    nickname CITEXT,
    birth_date DATE,
    email CITEXT,
    phone VARCHAR(50),
    address TEXT,
    notes TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    tags TEXT,
    contact_preference VARCHAR(50),
    last_contact_date TIMESTAMP,
    next_action_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    documents TEXT,
    archived_at TIMESTAMP,
    CONSTRAINT unique_registration_id_when_not_null UNIQUE (registration_id)
);

CREATE UNIQUE INDEX unique_name_when_no_registration ON clients(name) WHERE registration_id IS NULL;

CREATE TABLE IF NOT EXISTS dependents (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    client_id UUID NOT NULL,
    description TEXT,
    birth_date DATE,
    email CITEXT,
    phone VARCHAR(50),
    address TEXT,
    notes TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    tags TEXT,
    contact_preference VARCHAR(50),
    documents TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    CONSTRAINT unique_dependent_name_per_client UNIQUE (client_id, name)
);

CREATE TABLE IF NOT EXISTS categories (
    id UUID PRIMARY KEY,
    name CITEXT UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    archived_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS lines (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    category_id UUID NOT NULL,
    deleted_at TIMESTAMP,
    archived_at TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
    CONSTRAINT unique_line_name_per_category UNIQUE (category_id, name)
);

CREATE TABLE IF NOT EXISTS contracts (
    id UUID PRIMARY KEY,
    model CITEXT,
    product_key CITEXT UNIQUE,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    line_id UUID NOT NULL,
    client_id UUID NOT NULL,
    dependent_id UUID,
    archived_at TIMESTAMP,
    FOREIGN KEY (line_id) REFERENCES lines(id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (dependent_id) REFERENCES dependents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    operation VARCHAR(50) NOT NULL,
    entity VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    admin_id UUID,
    admin_username CITEXT,
    old_value TEXT,
    new_value TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'success',
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_method VARCHAR(10),
    request_path VARCHAR(512),
    request_id VARCHAR(100),
    response_code INTEGER,
    execution_time_ms INTEGER,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_id ON audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);
