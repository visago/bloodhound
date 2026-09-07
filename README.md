# bloodhound - HTTP Reverse Proxy Sniffer

This code was initially generated using [Claude](https://claude.ai/) and modified to fit my purpose.

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `TargetUrl` | `https://httpbin.org` | Target host URL |
| `ListenAddr` | **required** | Listen addr:port, e.g. `127.0.0.1:25663` |
| `BoneFolder` | *(empty)* | Folder to store sniffed bones to. Empty disables dumping |
| `TlsCert` | *(empty)* | PEM certificate (chain) to serve HTTPS with |
| `TlsKey` | *(empty)* | PEM private key matching `TlsCert` |
| `TlsAutoCert` | `false` | Serve HTTPS with a self-signed cert generated at startup |
| `TlsHosts` | `localhost,127.0.0.1,::1` | Comma separated SANs for the `TlsAutoCert` certificate |
| `TargetInsecure` | `false` | Do not verify the target's TLS certificate |
| `TargetCaCert` | *(empty)* | Extra CA bundle used to verify the target's certificate |

Note that the variable names are CamelCase, not the usual SCREAMING_SNAKE_CASE.

`ListenAddr` has no default and must be set - bloodhound prints its help and exits
if it is missing or is not an `addr:port`. `TargetUrl` is required too, but keeps a
default, so in practice you only hit that error by pointing it at something that
isn't an `http://` or `https://` URL.

`bloodhound -h` prints the same help, which lists every variable above.

```
ListenAddr=127.0.0.1:25663 TargetUrl=https://httpbin.org BoneFolder=./bones ./bin/bloodhound
```

Bind to `127.0.0.1` unless you actually want the sniffer reachable from the
network - captured bones routinely contain cookies, tokens and credentials.

## TLS

bloodhound always speaks TLS *outbound* when `TargetUrl` is an `https://` URL, so
sniffing an HTTPS target works out of the box. The `Tls*` variables control the
*inbound* side, i.e. whether clients talk HTTPS to bloodhound itself.

```
                 TlsCert / TlsKey / TlsAutoCert        TargetInsecure / TargetCaCert
   client  ---------------------------------->  bloodhound  ---------------------->  TargetUrl
              inbound TLS (this is the new bit)                    outbound TLS
```

Because bloodhound terminates the inbound connection, bones are always written in
plaintext regardless of TLS being enabled on either side.

### Quick start with a self-signed certificate

Good for a throwaway test; clients have to skip verification.

```
ListenAddr=127.0.0.1:25663 TlsAutoCert=true ./bin/bloodhound
curl -k https://localhost:25663/get
```

The SHA-256 fingerprint of the generated certificate is logged at startup so it can
be pinned. The certificate lives in memory only and changes on every restart.

### Running your own CA

For anything longer lived, issue a certificate from your own CA and teach the
clients to trust that CA. Then no `-k` / `InsecureSkipVerify` is needed anywhere.

`make certs` does the whole thing:

```
make certs
ListenAddr=127.0.0.1:25663 TlsCert=certs/bloodhound.crt TlsKey=certs/bloodhound.key ./bin/bloodhound
curl --cacert certs/ca.crt https://localhost:25663/get
```

It writes `certs/ca.crt` (install this on clients), `certs/ca.key` (keep private),
and the `certs/bloodhound.crt` + `certs/bloodhound.key` pair bloodhound serves.
Both keys are chmod 600 and the whole `certs/` folder is gitignored.

The certificate is issued for `localhost`, `bloodhound.local`, `127.0.0.1` and
`::1`, so `https://localhost:25663/` works out of the box. The `::1` entry matters:
`localhost` resolves to IPv6 first on most modern systems.

The names baked into the certificate are overridable:

```
make certs CERT_CN=sniffer.example.com \
  CERT_SAN="DNS:sniffer.example.com,DNS:localhost,IP:127.0.0.1,IP:::1"
```

`CERT_DIR` (default `certs`), `CERT_DAYS` (398) and `CA_DAYS` (3650) can be set the
same way. The targets are file based, so re-running `make certs` does nothing once
the files exist - regenerating the CA would invalidate it on every client that has
already installed it.

To reissue only the server certificate, say to add a hostname, delete the leaf and
rebuild. The CA is untouched, so clients that already trust it keep working:

```
rm certs/bloodhound.crt
make certs CERT_SAN="DNS:localhost,DNS:myhost.lan,IP:127.0.0.1,IP:::1"
```

To start over completely, including the CA, delete `certs/` by hand.

The rest of this section is what `make certs` runs, for when you want to issue the
certificates yourself or adapt them to an existing CA.

#### 1. Create the CA (once)

```
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/O=bloodhound/CN=bloodhound local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

`ca.key` signs every certificate you will ever issue - keep it private and offline
if you can. `ca.crt` is the public half you install into clients.

#### 2. Issue a server certificate for bloodhound

The SAN list matters: modern clients ignore the Common Name entirely and match the
hostname against `subjectAltName` only. List every name and IP clients will use to
reach bloodhound, and remember `localhost` resolves to `::1` before `127.0.0.1` on
most systems, so include both loopback addresses.

```
cat > bloodhound.ext <<'END'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:bloodhound.local, IP:127.0.0.1, IP:::1
END

openssl req -newkey rsa:2048 -nodes \
  -keyout bloodhound.key -out bloodhound.csr \
  -subj "/O=bloodhound/CN=localhost"

openssl x509 -req -in bloodhound.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out bloodhound.crt -days 398 -sha256 \
  -extfile bloodhound.ext
```

Keep `-days` at 398 or below: Apple and Chrome reject longer-lived server
certificates, even ones chaining to a manually trusted CA.

Check the result before deploying it:

```
openssl verify -CAfile ca.crt bloodhound.crt
openssl x509 -in bloodhound.crt -noout -subject -ext subjectAltName
```

#### 3. Point bloodhound at it

```
ListenAddr=127.0.0.1:25663 TlsCert=./bloodhound.crt TlsKey=./bloodhound.key ./bin/bloodhound
```

Keep the private keys to yourself: `chmod 600 ca.key bloodhound.key`.

If your CA uses an intermediate, `TlsCert` must contain the full chain - leaf
first, then the intermediate(s), root optional - concatenated into one PEM file.

### Trusting the CA on clients

Install `ca.crt` (never `ca.key`) wherever the client looks for trust anchors.

**curl** - per invocation, or via the environment:

```
curl --cacert /path/to/ca.crt https://bloodhound.local:25663/get
export CURL_CA_BUNDLE=/path/to/ca.crt
```

**Debian / Ubuntu** - system wide, the file must end in `.crt`:

```
sudo cp ca.crt /usr/local/share/ca-certificates/bloodhound-ca.crt
sudo update-ca-certificates
```

**RHEL / Fedora / CentOS**:

```
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/bloodhound-ca.crt
sudo update-ca-trust extract
```

**Alpine** (including inside containers):

```
apk add ca-certificates
cp ca.crt /usr/local/share/ca-certificates/bloodhound-ca.crt
update-ca-certificates
```

**macOS** - add to the system keychain and mark it trusted:

```
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.crt
```

**Windows** (elevated PowerShell):

```
Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

**Firefox** keeps its own store: Settings -> Privacy & Security -> Certificates ->
View Certificates -> Authorities -> Import, and tick "Trust this CA to identify
websites". Chrome and Edge use the OS store on Windows/macOS, and the NSS store on
Linux (`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n bloodhound-ca -i ca.crt`).

**Language runtimes** that bypass the system store:

| Runtime | How |
| --- | --- |
| Python `requests` | `export REQUESTS_CA_BUNDLE=/path/to/ca.crt` |
| Python `httpx`, `aiohttp` | `export SSL_CERT_FILE=/path/to/ca.crt` |
| Node.js | `export NODE_EXTRA_CA_CERTS=/path/to/ca.crt` |
| Go | `export SSL_CERT_FILE=/path/to/ca.crt` |
| Java | `keytool -importcert -cacerts -alias bloodhound-ca -file ca.crt` |

Note that Go only consults `SSL_CERT_FILE` on Unix, and Java needs the JDK's
`changeit` keystore password by default.

### Trusting the CA inside another container (Grafana, etc.)

A container has its own trust store, so installing the CA on the host does nothing
for the software inside it. If you want Grafana - or any other container - to talk
to bloodhound over HTTPS without disabling verification, the CA has to go into that
image.

Containers reach bloodhound by its compose service name, so the certificate needs a
SAN for it. The default `make certs` SAN list already includes `DNS:bloodhound` for
exactly this. If you renamed the service, reissue the leaf:

```
rm certs/bloodhound.crt
make certs CERT_SAN="DNS:localhost,DNS:my-service-name,IP:127.0.0.1,IP:::1"
```

#### Option A - bake the CA into a derived image

The most reliable option, and the one that works no matter what HTTP library the
application uses. Grafana is Alpine based:

```
# Dockerfile.grafana
FROM grafana/grafana:latest
USER root
COPY certs/ca.crt /usr/local/share/ca-certificates/bloodhound-ca.crt
RUN update-ca-certificates
USER grafana
```

For a Debian or Ubuntu based image the recipe is the same, only the user differs:

```
FROM some/debian-based-image:latest
USER root
COPY certs/ca.crt /usr/local/share/ca-certificates/bloodhound-ca.crt
RUN update-ca-certificates
USER 1000
```

The `USER root` / `USER <original>` dance matters: `update-ca-certificates` writes
to `/etc/ssl/certs`, and most images (Grafana runs as uid 472) are not root. Check
what the image uses before you switch back:

```
docker inspect grafana/grafana:latest --format '{{.Config.User}}'
```

Wire it up in compose:

```yaml
services:
  grafana:
    build:
      context: .
      dockerfile: Dockerfile.grafana
    ports:
      - "127.0.0.1:3000:3000"
    depends_on:
      - bloodhound
```

Grafana can now verify `https://bloodhound:25663/` on the compose network, and you
point its datasource at that URL instead of the real upstream.

#### Option B - no rebuild

You can avoid building an image entirely. Which method works depends on how the
application reaches its trust store, and Grafana is a good illustration of why the
obvious one is not enough.

**B1. Mount a merged CA bundle over the image's default trust file.** This is the
one to reach for: no rebuild, no root, no environment variables, and it covers
every process in the container including datasource plugins.

```
# build a bundle from the image's own roots plus your CA
docker run --rm --entrypoint cat grafana/grafana:latest \
  /etc/ssl/certs/ca-certificates.crt > certs/bundle.crt
cat certs/ca.crt >> certs/bundle.crt
```

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./certs/bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro
    ports:
      - "127.0.0.1:3000:3000"
```

Append to the image's own bundle rather than mounting `ca.crt` alone, otherwise the
container stops trusting every public CA. Rebuild the bundle when you update the
base image.

**B2. `SSL_CERT_FILE` plus plugin env forwarding.** Setting `SSL_CERT_FILE` on the
container is *not* enough for Grafana. It reaches the Grafana process, but
datasource backends run as separate plugin processes and Grafana passes them a
curated environment - `SSL_CERT_FILE` is stripped, and datasource queries keep
failing with `x509: certificate signed by unknown authority`. You can confirm this
yourself:

```
docker exec <container> printenv SSL_CERT_FILE     # set
docker exec <container> sh -c 'tr "\0" "\n" < /proc/<plugin pid>/environ | grep SSL'   # absent
```

Grafana has a setting for it - a comma separated list of plugin ids whose processes
inherit the host environment:

```yaml
    environment:
      SSL_CERT_FILE: /certs/ca.crt
      GF_PLUGINS_FORWARD_HOST_ENV_VARS: prometheus
    volumes:
      - ./certs/ca.crt:/certs/ca.crt:ro
```

List every datasource plugin id you route through bloodhound. This forwards the
*entire* host environment to those plugins, so keep the list narrow.

**B3. Give the CA to the datasource only.** The most targeted option, and it needs
nothing mounted at all - provision the CA inline:

```yaml
# provisioning/datasources/bloodhound.yaml
apiVersion: 1
datasources:
  - name: bh
    uid: bh
    type: prometheus
    access: proxy
    url: https://bloodhound:25663
    jsonData:
      tlsAuthWithCACert: true
    secureJsonData:
      tlsCACert: |
        -----BEGIN CERTIFICATE-----
        ...contents of certs/ca.crt, indented to match...
        -----END CERTIFICATE-----
```

All three were tested against `grafana/grafana:latest` (13.2.1) by provisioning a
Prometheus datasource at `https://bloodhound:25663` and calling
`/api/datasources/uid/<uid>/health`. Stock image: `x509: certificate signed by
unknown authority`. With any of B1, B2 or B3: the TLS error is gone and the request
shows up in bloodhound's log with `tlsServerName=bloodhound`.

For other runtimes the environment variables are:

| Runtime | Variable | Behaviour |
| --- | --- | --- |
| Go | `SSL_CERT_FILE` | Overrides the default CA file; child processes must inherit it |
| OpenSSL tools, curl | `SSL_CERT_FILE` / `CURL_CA_BUNDLE` | Overrides the default CA file |
| Node.js | `NODE_EXTRA_CA_CERTS` | Appends to the built in roots |
| Python `requests` | `REQUESTS_CA_BUNDLE` | Replaces the bundle |

Anything that hardcodes its own trust store, or spawns helpers with a scrubbed
environment as Grafana does, needs B1 or Option A.

#### Grafana specific

B3 above is the provisioned form of a setting you can also reach in the UI: in the
datasource settings enable **TLS/SSL Auth** -> **With CA Cert** and paste the
contents of `certs/ca.crt`. There is a **Skip TLS Verify** toggle next to it, which
works too but gives up the verification you set the CA up for.

`certs/bundle.crt` from B1 is gitignored along with everything else in `certs/`.

### Sniffing a target that uses a private CA

The same CA problem exists on the upstream side: if `TargetUrl` presents a
certificate from your internal CA, bloodhound has to trust it too.

```
ListenAddr=127.0.0.1:25663 TargetCaCert=/path/to/internal-ca.crt ./bin/bloodhound
```

`TargetCaCert` is *added* to the system roots rather than replacing them. As a last
resort `TargetInsecure=true` disables upstream verification entirely - it logs a
warning at startup, and it does mean anyone between bloodhound and the target can
impersonate the target.

## Docker Compose

`docker-compose.yaml` runs bloodhound with the certificates `make certs` produced:

```
make certs
docker compose up
curl --cacert certs/ca.crt https://localhost:25663/get
```

It mounts `./certs` read-only and `./bones` read-write, and publishes the port on
`127.0.0.1` only. `TargetUrl` can be set in the environment or a `.env` file:

```
TargetUrl=https://api.example.com docker compose up
```

Two things about it are deliberate. It **builds from the local Dockerfile** rather
than pulling `visago/bloodhound:latest`, because the published image predates TLS
support. And it runs as `${BLOODHOUND_UID:-1000}:${BLOODHOUND_GID:-1000}` rather
than the image's own `bloodhound` user: `make certs` writes the keys mode 600 owned
by you, so the container has to run as you to read them. If your uid is not 1000,
set `BLOODHOUND_UID`/`BLOODHOUND_GID` in a `.env` file, otherwise the container
exits with `open /certs/bloodhound.key: permission denied`.

## Docker

A dockered version is avilable at visago/bloodhound:latest

The image sets `ListenAddr=0.0.0.0:25663` so it runs without further configuration;
override it if you publish the port differently.

```
mkdir ./bones
chmod 777 ./bones # So the bloodhound user in docker can access it
docker run -p 25663:25663 -e TargetUrl=https://httpbin.org/  -e BoneFolder=/bones -v ./bones:/bones visago/bloodhound:latest
```

With TLS, mount the keypair in and make sure the unprivileged `bloodhound` user can
read the key:

```
docker run -p 25663:25663 \
  -e TargetUrl=https://httpbin.org/ \
  -e TlsCert=/certs/bloodhound.crt -e TlsKey=/certs/bloodhound.key \
  -e BoneFolder=/bones \
  -v ./bones:/bones -v ./certs:/certs:ro \
  visago/bloodhound:latest
```
