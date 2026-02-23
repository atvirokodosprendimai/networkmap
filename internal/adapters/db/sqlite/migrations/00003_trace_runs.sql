-- +goose Up
CREATE TABLE IF NOT EXISTS trace_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER NULL,
    start_entity_id INTEGER NOT NULL,
    target_entity_id INTEGER NULL,
    max_depth INTEGER NOT NULL,
    relation_keys TEXT NOT NULL DEFAULT '',
    hop_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_user_id) REFERENCES users(id),
    FOREIGN KEY (start_entity_id) REFERENCES entities(id),
    FOREIGN KEY (target_entity_id) REFERENCES entities(id)
);

CREATE INDEX IF NOT EXISTS idx_trace_runs_actor_created ON trace_runs(actor_user_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS trace_runs;
