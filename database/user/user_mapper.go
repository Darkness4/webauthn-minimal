package user

import (
	"encoding/json"

	"example-project/database"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func credentialFromModel(credential *database.Credential) webauthn.Credential {
	var transport []protocol.AuthenticatorTransport
	if err := json.Unmarshal(credential.Transport, &transport); err != nil {
		panic(err)
	}
	var flags webauthn.CredentialFlags
	if err := json.Unmarshal(credential.Flags, &flags); err != nil {
		panic(err)
	}
	var authenticator webauthn.Authenticator
	if err := json.Unmarshal(credential.Authenticator, &authenticator); err != nil {
		panic(err)
	}
	return webauthn.Credential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       transport,
		Flags:           flags,
		Authenticator:   authenticator,
	}
}

func fromModel(u *database.User, credentials []webauthn.Credential) *User {
	return &User{
		ID:          u.ID,
		Name:        u.Name,
		DisplayName: u.DisplayName,
		Credentials: credentials,
	}
}
