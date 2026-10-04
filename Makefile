.PHONY: build test lint vet fuzz list generate

# Every test, fuzz and CI run is built with the assertion tag, so a failed
# invariant panics instead of being recorded as Truncated "invariant".
TAGS := -tags softmagic_assert
FUZZTIME ?= 30s

build:
	go build ./...

test:
	go test $(TAGS) -race -count=1 ./...

vet:
	go vet $(TAGS) ./...

lint: vet
	go tool staticcheck $(TAGS) ./...
	go tool govulncheck ./...
	go tool gosec -quiet ./...
	go tool golangci-lint run ./...

fuzz:
	go test $(TAGS) -run=NONE -fuzz=FuzzCompile -fuzztime=$(FUZZTIME) .

# Regenerates the embedded compiled database from the vendored Magdir.
generate:
	SOFTMAGIC_GENERATE=1 go test $(TAGS) -run TestGenerateDatabase .

# Prints the compiled database in file -l order; diffed against the reference
# listing in testdata by TestListOracle.
list:
	go test $(TAGS) -run TestListOracle -v . | head -40
