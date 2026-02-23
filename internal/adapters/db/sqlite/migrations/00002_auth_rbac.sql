-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER NULL,
    metadata TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

INSERT OR IGNORE INTO roles(key, name) VALUES ('viewer', 'Viewer');
INSERT OR IGNORE INTO roles(key, name) VALUES ('operator', 'Operator');
INSERT OR IGNORE INTO permissions(key) VALUES ('graph.read');
INSERT OR IGNORE INTO permissions(key) VALUES ('graph.write');

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.key = 'viewer' AND p.key = 'graph.read';

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.key = 'operator' AND p.key = 'graph.read';

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.key = 'operator' AND p.key = 'graph.write';

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
