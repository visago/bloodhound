REVISION          := $(shell git rev-parse HEAD)
VERSION          := $(shell git describe --tags --always --dirty="-dev")
BRANCH          := $(shell git rev-parse --abbrev-ref HEAD)
DATE             := $(shell date -u '+%Y-%m-%dT%H:%M:%S+00:00')
VERSION_FLAGS    := -ldflags='-X "main.BuildVersion=$(VERSION)" -X "main.BuildRevision=$(REVISION)" -X "main.BuildTime=$(DATE)" -X "main.BuildBranch=$(BRANCH)"'

# Override these on the command line, e.g.
#   make certs CERT_SAN="DNS:sniffer.example.com,IP:10.0.0.5"
CERT_DIR         ?= certs
CERT_CN          ?= localhost
# localhost resolves to ::1 before 127.0.0.1 on many systems, so cover both.
# DNS:bloodhound is the docker-compose service name, so other containers on the
# same network can verify it too.
CERT_SAN         ?= DNS:localhost,DNS:bloodhound,DNS:bloodhound.local,IP:127.0.0.1,IP:::1
CERT_DAYS        ?= 398
CA_DAYS          ?= 3650

.PHONY: all build lint run clean docker certs

all:	lint build

build:
	go build -o bin/bloodhound ${VERSION_FLAGS} bloodhound.go

lint:
	gofmt -w bloodhound.go

run:
	go run ${VERSION_FLAGS} bloodhound.go
	
clean:
	rm -rf bin/bloodhound


docker:
	docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 -t visago/bloodhound:${VERSION} --push .
	docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 -t visago/bloodhound:latest --push .

# Generate the CA and the server certificate bloodhound serves HTTPS with.
# Both are file targets, so re-running this does nothing once they exist - the CA
# in particular must not be regenerated casually, that breaks every client which
# has already installed it. Delete $(CERT_DIR) by hand to start over.
certs: $(CERT_DIR)/bloodhound.crt
	@echo
	@echo "CA certificate to install on clients : $(CERT_DIR)/ca.crt"
	@echo "Run bloodhound with                  : ListenAddr=127.0.0.1:25663 TlsCert=$(CERT_DIR)/bloodhound.crt TlsKey=$(CERT_DIR)/bloodhound.key ./bin/bloodhound"
	@echo "Then                                 : curl --cacert $(CERT_DIR)/ca.crt https://localhost:25663/"
	@echo "See README.md for how to trust $(CERT_DIR)/ca.crt on each kind of client."

$(CERT_DIR)/ca.crt:
	@mkdir -p $(CERT_DIR)
	openssl req -x509 -newkey rsa:4096 -sha256 -days $(CA_DAYS) -nodes \
	  -keyout $(CERT_DIR)/ca.key -out $(CERT_DIR)/ca.crt \
	  -subj "/O=bloodhound/CN=bloodhound local CA" \
	  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
	  -addext "keyUsage=critical,keyCertSign,cRLSign"
	@chmod 600 $(CERT_DIR)/ca.key

$(CERT_DIR)/bloodhound.crt: $(CERT_DIR)/ca.crt
	@printf 'basicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = $(CERT_SAN)\n' > $(CERT_DIR)/bloodhound.ext
	openssl req -newkey rsa:2048 -nodes \
	  -keyout $(CERT_DIR)/bloodhound.key -out $(CERT_DIR)/bloodhound.csr \
	  -subj "/O=bloodhound/CN=$(CERT_CN)"
	openssl x509 -req -in $(CERT_DIR)/bloodhound.csr \
	  -CA $(CERT_DIR)/ca.crt -CAkey $(CERT_DIR)/ca.key -CAcreateserial \
	  -out $(CERT_DIR)/bloodhound.crt -days $(CERT_DAYS) -sha256 \
	  -extfile $(CERT_DIR)/bloodhound.ext
	@chmod 600 $(CERT_DIR)/bloodhound.key
	@rm -f $(CERT_DIR)/bloodhound.csr $(CERT_DIR)/bloodhound.ext
	openssl verify -CAfile $(CERT_DIR)/ca.crt $(CERT_DIR)/bloodhound.crt
