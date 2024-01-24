.PHONY: bin/webauthn
bin/webauthn: $(GO_SRCS)
	go build -trimpath -ldflags "-s -w" -o "$@" ./main.go

migrate := $(shell which migrate)
ifeq ($(migrate),)
migrate := $(shell go env GOPATH)/bin/migrate
endif

.PHONY: migration
migration: $(migrate)
	$(migrate) create -seq -ext sql -dir database/migrations $(MIGRATION_NAME)

.PHONY: up
up: $(MIGRATIONS) $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true up

.PHONY: drop
drop: $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true drop -f

$(migrate):
	go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate

sqlc := $(shell which sqlc)
ifeq ($(sqlc),)
sqlc := $(shell go env GOPATH)/bin/sqlc
endif

.PHONY: sql
sql: $(sqlc)
	$(sqlc) generate

$(sqlc):
	go install github.com/sqlc-dev/sqlc/cmd/sqlc

.PHONY: clean
clean:
	rm -rf bin/
