-- init.sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users ( -- Se trata dos usuários do sistema. Ex: admin, user1, user2, etc.
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_level INTEGER NOT NULL DEFAULT 0,
    locked_until DATETIME
);

CREATE TABLE IF NOT EXISTS clients ( -- Clients. E.g.: Client A, Client B, Person X, etc.
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    registration_id TEXT UNIQUE NOT NULL,
    email TEXT,
    phone TEXT,
    archived_at DATETIME
);

CREATE TABLE IF NOT EXISTS dependents ( -- Dependentes de cada cliente. Ex: Matriz, Filial SP, Filial RJ, Dependente, etc.
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client_id TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS categories ( -- Categorias de produtos. Ex: Sistema Operacional, Escritório, Antivírus, etc.
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS lines ( -- Linhas de produtos. Ex: Office, Windows, AutoCAD, etc.
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category_id TEXT NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contracts ( -- Contratos de software. Ex: Contrato do Windows 10 Pro, Contrato do Office 365, etc.
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    product_key TEXT UNIQUE NOT NULL,
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    line_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    dependent_id TEXT,
    archived_at DATETIME,
    FOREIGN KEY (line_id) REFERENCES lines(id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (dependent_id) REFERENCES dependents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs ( -- Logs de auditoria: rastreia todas as operações CRUD
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    operation TEXT NOT NULL, -- 'create', 'update', 'delete', 'read'
    entity TEXT NOT NULL, -- 'client', 'contract', 'user', 'line', 'category', 'dependent'
    entity_id TEXT NOT NULL,
    admin_id TEXT NOT NULL,
    admin_username TEXT,
    old_value TEXT, -- JSON com valores antigos (para updates/deletes)
    new_value TEXT, -- JSON com valores novos (para creates/updates)
    status TEXT NOT NULL DEFAULT 'success', -- 'success', 'error'
    error_message TEXT,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_id ON audit_logs(admin_id);
