-- +goose Up
ALTER TABLE logins ADD COLUMN kind TEXT NOT NULL DEFAULT 'terminal'
    CHECK (kind IN ('terminal', 'native'));
ALTER TABLE logins ADD COLUMN client_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE logins DROP COLUMN client_id;
ALTER TABLE logins DROP COLUMN kind;
