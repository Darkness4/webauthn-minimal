# Minimal WebAuthn

A minimal WebAuthn implementation in Go.

Summary:

- Full stack with Go templating + Pure Vanilla JS
- `go-webauthn` as WebAuthn library.
- WebAuthn as main authentication method.
- CSRF Protection.
- JWT sessions.
- Register/Login/Logout.
- Add/Remove additional devices.

## Usage

Quick run:

```shell
make run
```

```shell
Usage of ./bin/webauthn:
  -db.path string
        Path to the SQLite database (default "db.sqlite3")
  -http.addr string
        HTTP server address (default ":3000")
  -jwt.secret string
        JWT secret used for signing
  -public.url string
        Public URL of the HTTP server (default "http://localhost:3000")
```

## Documentation

- [Blog Post](https://blog.mnguyen.fr/blog/2024-01-27-webauthn-guide)

## License

Under [MIT](LICENSE) License.
