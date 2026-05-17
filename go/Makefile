.PHONY: build dist install test parity parity-decon tidy clean

BIN_DIR    := bin
DIST_DIR   := ../bin
BINS       := evm-check evm-diff evm-rule evm-audit evm-decon
GOOS       ?= $(shell go env GOOS)
GOARCH     ?= $(shell go env GOARCH)

build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINS); do \
		echo "build $$b"; \
		go build -o $(BIN_DIR)/$$b ./cmd/$$b || exit 1; \
	done

# dist: build platform-tagged binaries into repo-root bin/ for panel distribution.
# Run on each target platform (darwin/linux); CI matrix covers both.
# CGO_ENABLED=1 links against system libc (no Go toolchain needed at runtime).
dist:
	@mkdir -p $(DIST_DIR)
	@for b in $(BINS); do \
		OUT=$(DIST_DIR)/$$b-$(GOOS)-$(GOARCH); \
		echo "dist $$b → $$OUT"; \
		CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $$OUT ./cmd/$$b || exit 1; \
	done
	@echo "dist complete: $(GOOS)/$(GOARCH)"

install: build
	@cp $(BIN_DIR)/* $${GOBIN:-$$HOME/go/bin}/

test:
	go test ./...

parity: build
	go test ./test/parity/... -count=1

parity-decon: build
	go test ./test/parity/... -run TestDeconParity -count=1 -v

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)
