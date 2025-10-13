-- init.sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users ( -- Se trata dos usuários do sistema. Ex: admin, user1, user2, etc.
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS clients ( -- Clients. E.g.: Client A, Client B, Person X, etc.
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    registration_id TEXT UNIQUE NOT NULL,
    archived_at DATETIME -- Change from TEXT to DATETIME
);

CREATE TABLE IF NOT EXISTS entities ( -- Entidades de cada cliente. Ex: Matriz, Entidade SP, Entidade RJ, Dependente, etc.
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

CREATE TABLE IF NOT EXISTS licenses ( -- Licenças de software. Ex: Licença do Windows 10 Pro, Licença do Office 365, etc.
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    product_key TEXT UNIQUE NOT NULL,
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    line_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    entity_id TEXT,
    FOREIGN KEY (line_id) REFERENCES lines(id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL
);
