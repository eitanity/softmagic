.PHONY: build test lint vet fuzz list generate wctype

# Every test, fuzz and CI run is built with the assertion tag, so a failed
# invariant panics instead of being recorded as Truncated "invariant".
TAGS := -tags softmagic_assert
FUZZTIME ?= 30s
FUZZTARGETS := FuzzIdentify FuzzIdentifyAt FuzzCompile FuzzLoad FuzzLoadFields
# 386 has no coverage instrumentation, so there the fuzzer mutates blindly
# and replays the corpus amd64 built; it is the host where int is 32 bits.
FUZZARCHS := amd64 386

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

# Every fuzz target for FUZZTIME on each architecture, with the assertion
# tag and as released (where a failure is a real panic, not an assertion;
# "release" names no tag the module uses, so it builds the default way).
# -parallel=8 keeps the 386 harness within its address space.
fuzz:
	@set -e; for arch in $(FUZZARCHS); do for tags in softmagic_assert release; do \
		for target in $(FUZZTARGETS); do \
			echo "== $$target $$arch $$tags"; \
			GOARCH=$$arch go test -tags $$tags -run=NONE -fuzz="^$$target\$$" \
				-fuzztime=$(FUZZTIME) -parallel=8 .; \
		done; done; done

# Regenerates the embedded compiled database from the vendored Magdir.
generate:
	SOFTMAGIC_GENERATE=1 go test $(TAGS) -run TestGenerateDatabase .

# Prints the compiled database in file -l order; diffed against the reference
# listing in testdata by TestListOracle.
list:
	go test $(TAGS) -run TestListOracle -v . | head -40

# Regenerates the iswprint table from this host's glibc (see scripts/wctype.c).
wctype:
	cc -O2 -o .wctype scripts/wctype.c
	./.wctype softmagic > wctype.go
	rm -f .wctype
