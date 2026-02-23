-- +goose Up
CREATE TABLE IF NOT EXISTS entity_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS relation_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    directed INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_type_id) REFERENCES entity_types(id)
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_entity_id INTEGER NOT NULL,
    relation_type_id INTEGER NOT NULL,
    object_entity_id INTEGER NOT NULL,
    directed INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subject_entity_id) REFERENCES entities(id),
    FOREIGN KEY (relation_type_id) REFERENCES relation_types(id),
    FOREIGN KEY (object_entity_id) REFERENCES entities(id)
);

CREATE TABLE IF NOT EXISTS attribute_defs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    value_kind TEXT NOT NULL DEFAULT 'string',
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scope, key)
);

CREATE TABLE IF NOT EXISTS entity_attrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    attribute_def_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities(id),
    FOREIGN KEY (attribute_def_id) REFERENCES attribute_defs(id),
    UNIQUE(entity_id, attribute_def_id)
);

CREATE TABLE IF NOT EXISTS edge_attrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_id INTEGER NOT NULL,
    attribute_def_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (edge_id) REFERENCES edges(id),
    FOREIGN KEY (attribute_def_id) REFERENCES attribute_defs(id),
    UNIQUE(edge_id, attribute_def_id)
);

CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type_id);
CREATE INDEX IF NOT EXISTS idx_edges_subject ON edges(subject_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_object ON edges(object_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation_type_id);
CREATE INDEX IF NOT EXISTS idx_edges_state ON edges(state);

-- +goose Down
DROP TABLE IF EXISTS edge_attrs;
DROP TABLE IF EXISTS entity_attrs;
DROP TABLE IF EXISTS attribute_defs;
DROP TABLE IF EXISTS edges;
DROP TABLE IF EXISTS entities;
DROP TABLE IF EXISTS relation_types;
DROP TABLE IF EXISTS entity_types;
