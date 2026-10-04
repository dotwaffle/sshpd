-- name: CreateUser :one
INSERT INTO users (id, name) VALUES (?, ?) RETURNING *;

-- name: UserByName :one
SELECT * FROM users WHERE name = ?;

-- name: UserByID :one
SELECT * FROM users WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users ORDER BY name;

-- name: Credentials :many
SELECT * FROM credentials WHERE user_id = ? ORDER BY id;

-- name: PutInvitation :execrows
INSERT INTO invitations (user_id, secret_hash, expires, generation)
SELECT id, ?, ?, generation FROM users WHERE id = ? AND disabled = 0
ON CONFLICT (user_id) DO UPDATE SET secret_hash = excluded.secret_hash,
    expires = excluded.expires, generation = excluded.generation;

-- name: Invitation :one
SELECT users.* FROM invitations JOIN users ON users.id = invitations.user_id
WHERE secret_hash = ? AND expires > ? AND disabled = 0
    AND invitations.generation = users.generation;

-- name: ConsumeInvitation :one
DELETE FROM invitations WHERE secret_hash = ? AND expires > ? AND user_id = ?
    AND generation = ? RETURNING user_id;

-- name: InsertCredential :exec
INSERT INTO credentials (id, user_id, data) VALUES (?, ?, ?);

-- name: UpdateCredential :execrows
UPDATE credentials SET data = ?, version = version + 1
WHERE id = ? AND user_id = ? AND version = ?;

-- name: InsertLogin :exec
INSERT INTO logins (id, user_id, credential_id, secret_hash, expires, kind, client_id)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: Login :one
SELECT logins.id, logins.user_id, logins.kind, logins.client_id, logins.expires FROM logins
JOIN users ON users.id = logins.user_id
JOIN credentials ON credentials.id = logins.credential_id
WHERE secret_hash = ? AND expires > ? AND disabled = 0;

-- name: LoginByID :one
SELECT logins.id, logins.user_id, logins.kind, logins.client_id, logins.expires FROM logins
JOIN users ON users.id = logins.user_id
JOIN credentials ON credentials.id = logins.credential_id
WHERE logins.id = ? AND expires > ? AND disabled = 0;

-- name: NativeLogoutIdentity :one
SELECT logins.id FROM logins
JOIN users ON users.id = logins.user_id
JOIN credentials ON credentials.id = logins.credential_id
WHERE secret_hash = ? AND kind = 'native' AND disabled = 0;

-- name: DeleteLogin :one
DELETE FROM logins WHERE id = ? RETURNING user_id;

-- name: CredentialLogins :many
SELECT id FROM logins WHERE credential_id = ? AND user_id = ?;

-- name: DeleteCredential :execrows
DELETE FROM credentials WHERE id = ? AND user_id = ?;

-- name: RevokeUserLogins :exec
DELETE FROM logins WHERE user_id = ?;

-- name: DeleteInvitations :exec
DELETE FROM invitations WHERE user_id = ?;

-- name: DeleteCredentials :exec
DELETE FROM credentials WHERE user_id = ?;

-- name: SetUserState :exec
UPDATE users SET disabled = ?, generation = generation + 1 WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: ClearLogins :exec
DELETE FROM logins;

-- name: ClearInvitations :exec
DELETE FROM invitations;

-- name: ExpireLogins :exec
DELETE FROM logins WHERE expires <= ?;

-- name: ExpireInvitations :exec
DELETE FROM invitations WHERE expires <= ?;
