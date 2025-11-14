-- init.sql adaptado para PostgreSQL

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    display_name VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,
    role VARCHAR(50),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_level INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    registration_id VARCHAR(255),
    nickname VARCHAR(255),
    birth_date DATE,
    email VARCHAR(255),
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
    name VARCHAR(255) NOT NULL,
    client_id UUID NOT NULL,
    description TEXT,
    birth_date DATE,
    email VARCHAR(255),
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
    name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS lines (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category_id UUID NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contracts (
    id UUID PRIMARY KEY,
    model VARCHAR(255),
    product_key VARCHAR(255) UNIQUE,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
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
    entity_id UUID NOT NULL,
    admin_id UUID,
    admin_username VARCHAR(255),
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
