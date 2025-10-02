-- init.sql

PRAGMA foreign_keys = ON;

-- Tabela para as empresas (clientes)
CREATE TABLE IF NOT EXISTS companies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cnpj TEXT UNIQUE NOT NULL,
    archived_at DATETIME -- Mudar de TEXT para DATETIME
);

-- Tabela para as unidades/filiais de cada empresa
CREATE TABLE IF NOT EXISTS units (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    company_id TEXT NOT NULL,
    -- Mantemos o ON DELETE CASCADE para a deleção permanente (LGPD)
    FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE
);

-- (O resto das tabelas 'categories', 'types', 'licenses' permanecem iguais)
CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS types (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category_id TEXT NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories (id)
);

CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    product_key TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    type_id TEXT NOT NULL,
    company_id TEXT NOT NULL,
    unit_id TEXT,
    FOREIGN KEY (type_id) REFERENCES types (id),
    FOREIGN KEY (company_id) REFERENCES companies (id),
    -- Se a empresa for apagada permanentemente, suas licenças também devem ir
    FOREIGN KEY (unit_id) REFERENCES units (id) ON DELETE CASCADE
);
