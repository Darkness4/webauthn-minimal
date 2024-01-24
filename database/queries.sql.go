// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0
// source: queries.sql

package database

import (
	"context"
)

const createCredential = `-- name: CreateCredential :exec
INSERT INTO credentials (id, public_key, attestation_type, transport, flags, authenticator, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)
`

type CreateCredentialParams struct {
	ID              []byte
	PublicKey       []byte
	AttestationType string
	Transport       []byte
	Flags           []byte
	Authenticator   []byte
	UserID          []byte
}

func (q *Queries) CreateCredential(ctx context.Context, arg CreateCredentialParams) error {
	_, err := q.db.ExecContext(ctx, createCredential,
		arg.ID,
		arg.PublicKey,
		arg.AttestationType,
		arg.Transport,
		arg.Flags,
		arg.Authenticator,
		arg.UserID,
	)
	return err
}

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, name, display_name) VALUES (?, ?, ?) RETURNING id, name, display_name
`

type CreateUserParams struct {
	ID          []byte
	Name        string
	DisplayName string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.ID, arg.Name, arg.DisplayName)
	var i User
	err := row.Scan(&i.ID, &i.Name, &i.DisplayName)
	return i, err
}

const deleteCredential = `-- name: DeleteCredential :exec
DELETE FROM credentials WHERE id = ? AND user_id = ?
`

type DeleteCredentialParams struct {
	ID     []byte
	UserID []byte
}

func (q *Queries) DeleteCredential(ctx context.Context, arg DeleteCredentialParams) error {
	_, err := q.db.ExecContext(ctx, deleteCredential, arg.ID, arg.UserID)
	return err
}

const getCredentialsByUser = `-- name: GetCredentialsByUser :many
SELECT id, public_key, attestation_type, transport, flags, authenticator, user_id FROM credentials WHERE user_id = ?
`

func (q *Queries) GetCredentialsByUser(ctx context.Context, userID []byte) ([]Credential, error) {
	rows, err := q.db.QueryContext(ctx, getCredentialsByUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Credential
	for rows.Next() {
		var i Credential
		if err := rows.Scan(
			&i.ID,
			&i.PublicKey,
			&i.AttestationType,
			&i.Transport,
			&i.Flags,
			&i.Authenticator,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUser = `-- name: GetUser :one
SELECT id, name, display_name FROM users WHERE id = ? LIMIT 1
`

// database/queries.sql
func (q *Queries) GetUser(ctx context.Context, id []byte) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, id)
	var i User
	err := row.Scan(&i.ID, &i.Name, &i.DisplayName)
	return i, err
}

const getUserByName = `-- name: GetUserByName :one
SELECT id, name, display_name FROM users WHERE name = ? LIMIT 1
`

func (q *Queries) GetUserByName(ctx context.Context, name string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByName, name)
	var i User
	err := row.Scan(&i.ID, &i.Name, &i.DisplayName)
	return i, err
}

const updateCredential = `-- name: UpdateCredential :exec
UPDATE credentials
SET public_key = ?,
attestation_type = ?,
transport = ?,
flags = ?,
authenticator = ?
WHERE id = ?6
`

type UpdateCredentialParams struct {
	PublicKey       []byte
	AttestationType string
	Transport       []byte
	Flags           []byte
	Authenticator   []byte
	ByID            []byte
}

func (q *Queries) UpdateCredential(ctx context.Context, arg UpdateCredentialParams) error {
	_, err := q.db.ExecContext(ctx, updateCredential,
		arg.PublicKey,
		arg.AttestationType,
		arg.Transport,
		arg.Flags,
		arg.Authenticator,
		arg.ByID,
	)
	return err
}
