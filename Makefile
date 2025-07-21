REVISION          := $(shell git rev-parse HEAD)
VERSION          := $(shell git describe --tags --always --dirty="-dev")
BRANCH          := $(shell git rev-parse --abbrev-ref HEAD)
DATE             := $(shell date -u '+%Y-%m-%dT%H:%M:%S+00:00')
VERSION_FLAGS    := -ldflags='-X "main.BuildVersion=$(VERSION)" -X "main.BuildRevision=$(REVISION)" -X "main.BuildTime=$(DATE)" -X "main.BuildBranch=$(BRANCH)"'

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
	