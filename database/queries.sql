-- database/queries.sql
-- name: GetUser :one
SELECT * FROM users WHERE id = ? LIMIT 1;

-- name: GetUserByName :one
SELECT * FROM users WHERE name = ? LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (id, name, display_name) VALUES (?, ?, ?) RETURNING *;

-- name: CreateCredential :exec
INSERT INTO credentials (id, public_key, attestation_type, transport, flags, authenticator, user_id) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: UpdateCredential :exec
UPDATE credentials
SET public_key = ?,
attestation_type = ?,
transport = ?,
flags = ?,
authenticator = ?
WHERE id = sqlc.arg(by_id);

-- name: DeleteCredential :exec
DELETE FROM credentials WHERE id = ? AND user_id = ?;

-- name: GetCredentialsByUser :many
SELECT * FROM credentials WHERE user_id = ?;
