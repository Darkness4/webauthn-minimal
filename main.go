package main

import (
	"database/sql"
	"embed"
	"encoding/base64"
	"example-project/database"
	"example-project/database/user"
	"example-project/jwt"
	internalwebauthn "example-project/webauthn"
	"example-project/webauthn/session"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/csrf"
)

var (
	//go:embed pages/* base.html
	pages embed.FS
)

var (
	jwtSecretFlag  = flag.String("jwt.secret", "", "JWT secret used for signing")
	csrfSecretFlag = flag.String("csrf.secret", "", "CSRF secret used for signing")
	httpAddrFlag   = flag.String("http.addr", ":3000", "HTTP server address")
	publicURLFlag  = flag.String(
		"public.url",
		"http://localhost:3000",
		"Public URL of the HTTP server",
	)
	dbPathFlag = flag.String("db.path", "db.sqlite3", "Path to the SQLite database")
)

func main() {
	flag.Parse()

	if *jwtSecretFlag == "" {
		slog.Error("missing jwt.secret flag")
		os.Exit(1)
	}

	// DB
	d, err := sql.Open("sqlite", *dbPathFlag)
	if err != nil {
		slog.Error("db failed", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if err := database.InitialMigration(d); err != nil {
		slog.Error("db migration failed", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Create the JWT secret
	jwtSecret := jwt.Secret(*jwtSecretFlag)

	// WebAuthn
	u, err := url.Parse(*publicURLFlag)
	if err != nil {
		slog.Error("failed to parse public URL", slog.String("err", err.Error()))
		os.Exit(1)
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WebAuthn Demo", // Display Name for your site
		RPID:          u.Hostname(),    // Generally the domain name for your site
		RPOrigin:      *publicURLFlag,  // The origin URL for WebAuthn requests
	})
	if err != nil {
		panic(err)
	}

	webauthnS := internalwebauthn.New(
		webAuthn,
		user.NewRepository(d),
		session.NewInMemory(),
		jwt.Secret(jwtSecret),
	)

	// Router
	r := chi.NewRouter()
	r.Use(jwtSecret.Middleware)
	r.Get("/logout", internalwebauthn.Logout)
	r.Route("/login", func(r chi.Router) {
		r.Get("/begin", webauthnS.BeginLogin())
		r.Post("/finish", webauthnS.FinishLogin())
	})
	r.Route("/register", func(r chi.Router) {
		r.Get("/begin", webauthnS.BeginRegistration())
		r.Post("/finish", webauthnS.FinishRegistration())
	})
	r.Route("/add-device", func(r chi.Router) {
		r.Get("/begin", webauthnS.BeginAddDevice())
		r.Post("/finish", webauthnS.FinishAddDevice())
	})
	r.Post("/delete-device", webauthnS.DeleteDevice())

	renderFn := func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Clean(r.URL.Path)
		if path == "/" || path == "." {
			path = "index"
		}
		path = strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/")
		path = fmt.Sprintf("pages/%s.html", path)

		t, err := template.ParseFS(pages, "base.html", path)
		if err != nil {
			if strings.Contains(err.Error(), "no files") {
				http.Error(w, "not found", http.StatusNotFound)
			} else {
				slog.Error("template error", slog.String("err", err.Error()))
				panic(err)
			}
			return
		}

		claims, _ := jwt.GetClaimsFromRequest(r)
		creds := make([]string, 0, len(claims.Credentials))
		for _, c := range claims.Credentials {
			creds = append(creds, base64.RawURLEncoding.EncodeToString(c.ID))
		}
		if err := t.ExecuteTemplate(w, "base", struct {
			CSRFToken   string
			UserName    string
			Credentials []string
		}{
			CSRFToken:   csrf.Token(r),
			UserName:    claims.Subject,
			Credentials: creds,
		}); err != nil {
			slog.Error("template error", slog.String("err", err.Error()))
			panic(err)
		}
	}

	r.Route("/protected", func(r chi.Router) {
		r.Use(jwt.Deny)
		r.Get("/", renderFn)
	})
	r.Get("/*", renderFn)

	slog.Info("http server started", slog.String("addr", *httpAddrFlag))
	if err := http.ListenAndServe(*httpAddrFlag, csrf.Protect([]byte(*csrfSecretFlag))(r)); err != nil {
		slog.Error("http server failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}
