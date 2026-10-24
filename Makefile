GO        ?= go
GOLANGCI_LINT ?= golangci-lint
BIN       := bin/attestlog
COVER_MIN ?= 80
export GOFLAGS ?= -p=3

.PHONY: all build check fmt-check fmt lint vet test race cover fuzz bench demo clean

all: check

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/attestlog

## check: the single gate — format, lint, vet/type-check, race tests, coverage
check: fmt-check lint vet race cover

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

fmt:
	gofmt -w .

lint:
	$(GOLANGCI_LINT) run ./...

vet:
	$(GO) build ./...
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -count=1 -race ./...

cover:
	./scripts/coverage.sh $(COVER_MIN)

## fuzz: run each fuzz target briefly (seeds always run as part of `make test`)
fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzVerifyInclusion -fuzztime=20s ./pkg/merkle
	$(GO) test -run=^$$ -fuzz=FuzzVerify -fuzztime=20s ./pkg/dsse
	$(GO) test -run=^$$ -fuzz=FuzzOpen -fuzztime=20s ./pkg/note
	$(GO) test -run=^$$ -fuzz=FuzzParse -fuzztime=20s ./pkg/checkpoint

bench:
	$(GO) test -run=^$$ -bench=. -benchmem -count=1 ./pkg/merkle ./pkg/keys

demo: build
	./scripts/demo.sh

clean:
	rm -rf bin .demo coverage.out
