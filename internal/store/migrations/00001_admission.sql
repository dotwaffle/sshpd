-- +goose Up
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE credentials (
    id BLOB PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX credentials_user ON credentials(user_id);
CREATE TABLE invitations (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    expires INTEGER NOT NULL,
    generation INTEGER NOT NULL
);
CREATE TABLE logins (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    expires INTEGER NOT NULL
);
CREATE INDEX logins_user ON logins(user_id);
CREATE INDEX logins_credential ON logins(credential_id);

-- +goose Down
DROP TABLE logins;
DROP TABLE invitations;
DROP TABLE credentials;
DROP TABLE users;
