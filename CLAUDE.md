# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`bloodhound` is a single-binary Go **reverse proxy sniffer**. It fronts one upstream
target, logs every request/response as structured JSON (zerolog), and optionally
dumps the full raw request and response (headers + body) to "bone" files on disk.

Despite the "man in the middle" framing: this is a *reverse* proxy
(`httputil.NewSingleHostReverseProxy`) bound to a single `TargetUrl`. It does not
implement HTTP `CONNECT`, does not forge certificates per-SNI, and cannot be used
as a system-wide forward proxy. Clients must be pointed at `ListenAddr` explicitly.

TLS is terminated on both sides independently: clients may speak HTTPS to
bloodhound (`Tls*` vars), and bloodhound speaks HTTPS to the target whenever
`TargetUrl` is `https://` (`Target*` vars tune verification). Bones are therefore
always plaintext, whatever TLS is in play.

## Layout

The entire program is `bloodhound.go` (~450 lines, `package main`). There are no
other packages, no tests, and no test framework wired up.

- `bloodhound.go` — everything: config, proxy, sniffing, file dumping, `main()`
- `Makefile` — build / lint / run / clean / docker targets
- `Dockerfile` — two-stage golang:alpine → alpine, runs as non-root `bloodhound`
- `docker-compose.yaml` — runs the local build against `certs/` from `make certs`
- `bones/`, `bin/` — untracked local output; never commit them

## Build and run

```
make            # lint + build
make build      # -> bin/bloodhound
make lint       # gofmt -w bloodhound.go  (that's the whole linter)
make run        # go run
make docker     # buildx multi-arch, PUSHES to visago/bloodhound — don't run casually
make certs      # generate certs/{ca,bloodhound}.{crt,key} for the TLS listener
```

`certs` is a file target, not a phony one: once `certs/ca.crt` exists it is never
rebuilt, because regenerating the CA silently breaks every client that installed
it. `CERT_DIR`/`CERT_CN`/`CERT_SAN`/`CERT_DAYS`/`CA_DAYS` override the defaults. The
leaf covers `localhost`, `bloodhound.local`, `127.0.0.1` and `::1` — keep `::1`,
`localhost` resolves to IPv6 first on most systems and a v4-only cert fails there.
`rm certs/bloodhound.crt && make certs` reissues just the leaf, keeping the CA (and
therefore every client's trust) intact.
Nothing under `certs/` is tracked — `.gitignore` covers `/certs`, `*.key`, `*.crt`
and `*.srl`.

`go vet ./...` is clean; keep it that way.

Run it:

```
ListenAddr=127.0.0.1:25663 TargetUrl=https://httpbin.org BoneFolder=./bones ./bin/bloodhound
curl http://localhost:25663/get

# or with TLS
ListenAddr=127.0.0.1:25663 TlsAutoCert=true ./bin/bloodhound
curl -k https://localhost:25663/get

./bin/bloodhound -h    # prints usageText, the only flag it accepts
```

## Configuration

Env vars only — the sole accepted argument is `-h`/`--help`, and anything else is a
fatal error (`parseArgs`). Parsed by `caarlos0/env/v11`, and note the env var names
are **CamelCase**, not the usual SCREAMING_SNAKE:

| Var | Default | Meaning |
| --- | --- | --- |
| `TargetUrl` | `https://httpbin.org` | Upstream to proxy to |
| `ListenAddr` | **required** | Listen address, `addr:port` |
| `BoneFolder` | *(empty)* | Where to dump bone files; empty disables dumping |
| `TlsCert` / `TlsKey` | *(empty)* | Serve HTTPS with this keypair; both or neither |
| `TlsAutoCert` | `false` | Serve HTTPS with a self-signed cert made at startup |
| `TlsHosts` | `localhost,127.0.0.1,::1` | SANs for the `TlsAutoCert` cert (comma separated) |
| `TargetInsecure` | `false` | Skip upstream certificate verification |
| `TargetCaCert` | *(empty)* | Extra CA bundle for upstream verification |

## Things that will bite you

- **`caarlos0/env` falls back to `envDefault` when a variable is set but empty.**
  `TargetUrl= ./bin/bloodhound` runs against httpbin, it does not fail. So the
  empty-string checks in `validateConfig` are unreachable through the environment
  for any field that has a default — `ListenAddr` is catchable only because its
  default was deliberately removed. Don't add a default to a field you want to
  force the user to supply.
- **Other containers need the CA installed inside them**, not on the host, and
  `SSL_CERT_FILE` alone is a trap: Grafana strips it from the datasource plugin
  subprocesses it spawns, so queries still fail with `unknown authority` while the
  variable is plainly set on PID 1. Mounting a merged bundle over the image's
  `/etc/ssl/certs/ca-certificates.crt` is the reliable no-rebuild route. README has
  all four options. The default cert SAN list includes `DNS:bloodhound`, the compose
  service name, so container-to-container TLS verifies without extra work.
- **Compose must override the container user.** The image's `bloodhound` user
  cannot read the mode-600 keys `make certs` writes on the host, so
  `docker-compose.yaml` sets `user: "${BLOODHOUND_UID:-1000}:..."`. Dropping that
  line gives `open /certs/bloodhound.key: permission denied` at startup. It also
  builds locally on purpose — the pushed `visago/bloodhound:latest` has no TLS.
- **`usage()` writes plain text to stderr while everything else is zerolog JSON.**
  On a config error you get the help text followed by one JSON `fatal` line; that
  ordering is intentional so the actual error is the last thing on screen.
- **`ListenAndServeTLS` is called with empty strings in the `TlsAutoCert` path.**
  That is deliberate — it makes net/http fall back to `server.TLSConfig.Certificates`
  rather than reading files from disk. Don't "fix" it by passing paths.
- **The auto-generated cert is in-memory and regenerates on every restart**, so its
  fingerprint changes and any client pinning it breaks. It is a testing convenience;
  anything persistent wants a real keypair in `TlsCert`/`TlsKey`.
- **`TargetCaCert` appends to the system pool, it does not replace it.** If
  `x509.SystemCertPool()` fails the code falls back to an empty pool, which would
  silently narrow trust to just that file.
- **Request/response bone files for the same exchange have different timestamps.**
  Both filenames are `<YYYYMMDD-HHMMSS>-<%06d id>-{request,response}.txt`, but each
  timestamp is taken at write time. Pair files by the zero-padded request ID, never
  by the timestamp.
- **Bodies are fully buffered.** `writeRequestToFile`/`writeResponseToFile` do
  `io.ReadAll` and then replace the body with a `NopCloser` over the bytes. That
  means large uploads/downloads sit in RAM, and streaming responses (SSE, chunked
  long-poll, websockets upgrades) will not stream while `BoneFolder` is set.
- **The Director rewrites `req.Host` to the target host.** This is needed for
  vhosted and SNI-strict upstreams, but it means bone files record the *upstream*
  Host, not the one the client sent. Look at `tlsServerName` in the completed log
  line if you need the name the client asked for.
- **The request ID travels in `context` under a plain `string` key**
  (`const requestIDKey = "requestID"`). It is read back with an unchecked
  `.(int64)` assertion in the `Director` and `ModifyResponse` hooks. If you add
  another context value, keep the type consistent or those hooks will panic.
- **The Makefile injects `main.BuildVersion` / `BuildRevision` / `BuildTime` /
  `BuildBranch` via `-ldflags -X`, but none of those variables exist in the
  source.** The linker silently ignores them. If you want a `--version` output,
  declare the four package-level `var`s first.
- **Dumping is best-effort.** Write errors are logged and swallowed; a failed
  `io.ReadAll` silently drops the body from the dump but still proxies fine.

## Conventions

- Logging is `github.com/rs/zerolog/log` with structured fields. Every log line
  carries `phase` (`request` / `response` / `completed`) and `id` (the request ID).
  Keep that pairing when adding log lines.
- Formatting is plain `gofmt`. Run `make lint` before committing.
- The repo contains `*~` editor backups (joe) which are gitignored, and an
  untracked `DEADJOE` crash file. Leave them alone; don't commit them.
