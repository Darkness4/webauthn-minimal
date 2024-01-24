// Package webauthn handles WebAuthn related functionalities.
package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"example-project/database/user"
	"example-project/jwt"
	"example-project/webauthn/session"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Service prepares WebAuthn handlers.
type Service struct {
	webAuthn  *webauthn.WebAuthn
	jwtSecret jwt.Secret
	users     user.Repository
	store     session.Store
}

// New instanciates a Webauthn Service.
func New(
	webAuthn *webauthn.WebAuthn,
	users user.Repository,
	store session.Store,
	jwtSecret jwt.Secret,
) *Service {
	if webAuthn == nil {
		panic("webAuthn is nil")
	}
	if users == nil {
		panic("users is nil")
	}
	if store == nil {
		panic("store is nil")
	}
	return &Service{
		webAuthn:  webAuthn,
		users:     users,
		store:     store,
		jwtSecret: jwtSecret,
	}
}

// BeginLogin is the handler called to generate options for the user's authenticator.
func (s *Service) BeginLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		options, session, err := s.webAuthn.BeginLogin(user)
		if err != nil {
			slog.Error(
				"user failed to begin login",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		if err := s.store.Save(r.Context(), session); err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		o, err := json.Marshal(options)
		if err != nil {
			slog.Error("failed to respond", slog.String("err", err.Error()), slog.Any("user", user))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(o)
	}
}

// FinishLogin is the handler called after the user's authenticator sent its payload.
func (s *Service) FinishLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session, err := s.store.Get(r.Context(), user.ID)
		if err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credential, err := s.webAuthn.FinishLogin(user, *session, r)
		if err != nil {
			slog.Error(
				"user failed to finish login",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// At this point, we've confirmed the correct authenticator has been
		// provided and it passed the challenge we gave it. We now need to make
		// sure that the sign counter is higher than what we have stored to help
		// give assurance that this credential wasn't cloned.
		if credential.Authenticator.CloneWarning {
			slog.Error("credential appears to be cloned", slog.Any("credential", credential))
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// If login was successful, update the credential object
		if err := s.users.UpdateCredential(r.Context(), credential); err != nil {
			slog.Error(
				"user failed to update credential during finish login",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info("user logged", slog.Any("credential", credential), slog.Any("user", user))

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			user.Credentials,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// BeginRegistration beings the webauthn flow.
//
// Based on the user identity, webauthn will generate options for the authenticator.
// We send the options over JSON (not very htmx).
func (s *Service) BeginRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetOrCreateByName(r.Context(), name) // Find or create the new user
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(user.Credentials) > 0 {
			// The user has already been registered. We must login.
			http.Error(w, "the user is already registered", http.StatusForbidden)
			return
		}
		registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
			credCreationOpts.CredentialExcludeList = user.ExcludeCredentialDescriptorList()
		}
		options, session, err := s.webAuthn.BeginRegistration(user, registerOptions)
		if err != nil {
			slog.Error(
				"user failed to begin registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		if err := s.store.Save(r.Context(), session); err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		o, err := json.Marshal(options)
		if err != nil {
			panic(err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(o)
	}
}

// FinishRegistration finishes the webauthn flow.
//
// The user has created options based on the options. We fetch the registration
// session from the session store.
// We complete the registration.
func (s *Service) FinishRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session, err := s.store.Get(r.Context(), user.ID)
		if err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credential, err := s.webAuthn.FinishRegistration(user, *session, r)
		if err != nil {
			slog.Error(
				"user failed to finish registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If creation was successful, store the credential object
		if err := s.users.AddCredential(r.Context(), user.ID, credential); err != nil {
			slog.Error(
				"user failed to add credential during registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("username", name),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info("user registered", slog.Any("credential", credential), slog.Any("user", user))

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			user.Credentials,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// BeginAddDevice beings the webauthn registration flow.
//
// Based on the user identity, webauthn will generate options for the authenticator.
// We send the options over JSON (not very htmx).
//
// Compared to BeginRegistration, BeginAddDevice uses the JWT to allow the registration.
func (s *Service) BeginAddDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			slog.Error(
				"failed to parse claims",
				slog.String("err", err.Error()),
				slog.Any("claims", claims),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("userid", string(userID)),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
			credCreationOpts.CredentialExcludeList = user.ExcludeCredentialDescriptorList()
		}
		options, session, err := s.webAuthn.BeginRegistration(user, registerOptions)
		if err != nil {
			slog.Error(
				"user failed to begin new device registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		if err := s.store.Save(r.Context(), session); err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		o, err := json.Marshal(options)
		if err != nil {
			panic(err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(o)
	}
}

// FinishAddDevice finishes the webauthn registration flow.
//
// The user has created options based on the options. We fetch the registration
// session from the session store.
// We complete the registration.
func (s *Service) FinishAddDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			slog.Error(
				"failed to parse claims",
				slog.String("err", err.Error()),
				slog.Any("claims", claims),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("userid", string(userID)),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session, err := s.store.Get(r.Context(), user.ID)
		if err != nil {
			// Maybe a Fatal or Panic should be user here.
			slog.Error(
				"failed to save session in store",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credential, err := s.webAuthn.FinishRegistration(user, *session, r)
		if err != nil {
			slog.Error(
				"user failed to finish registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If creation was successful, store the credential object
		if err := s.users.AddCredential(r.Context(), user.ID, credential); err != nil {
			slog.Error(
				"user failed to add credential during registration",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("userid", string(userID)),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Error("device added", slog.Any("credential", credential), slog.Any("user", user))

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			user.Credentials,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// DeleteDevice deletes a webauthn credential.
func (s *Service) DeleteDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		credential := r.URL.Query().Get("credential")
		if credential == "" {
			http.Error(w, "empty credential", http.StatusBadRequest)
			return
		}

		cred, err := base64.RawURLEncoding.DecodeString(credential)
		if err != nil {
			slog.Error(
				"failed to parse credential",
				slog.String("err", err.Error()),
				slog.String("credential", credential),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			slog.Error(
				"failed to parse claims",
				slog.String("err", err.Error()),
				slog.Any("claims", claims),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
		if err != nil {
			slog.Error(
				"failed to fetch user",
				slog.String("err", err.Error()),
				slog.String("userid", string(userID)),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(user.Credentials) <= 1 {
			http.Error(w, "last credential cannot be deleted", http.StatusForbidden)
			return
		}

		// If creation was successful, store the credential object
		if err := s.users.RemoveCredential(r.Context(), user.ID, cred); err != nil {
			slog.Error(
				"user failed to remove credential",
				slog.String("err", err.Error()),
				slog.Any("user", user),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// Logout removes session cookies and redirect to home.
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(jwt.TokenCookieKey)
	if err != nil {
		// Ignore error. Cookie doesn't exists.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cookie.Value = ""
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(-1 * time.Hour)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
