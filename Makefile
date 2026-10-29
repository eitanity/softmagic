.PHONY: build test lint vet fuzz cross emulated list generate wctype

# Every test, fuzz and CI run is built with the assertion tag, so a failed
# invariant panics instead of being recorded as Truncated "invariant".
TAGS := -tags softmagic_assert
FUZZTIME ?= 30s
FUZZTARGETS := FuzzIdentify FuzzIdentifyAt FuzzCompile FuzzLoad FuzzLoadFields \
	FuzzELF FuzzCDF FuzzDER FuzzPString FuzzRule
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

# go vet for every platform the library is built for, without cgo.
CROSS := linux/386 linux/arm linux/arm64 linux/ppc64le linux/s390x linux/mips linux/riscv64 \
	darwin/amd64 darwin/arm64 freebsd/amd64 openbsd/amd64 windows/amd64 windows/arm64
cross:
	@set -e; for p in $(CROSS); do echo "== $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go vet $(TAGS) ./...; done

# The tests on other architectures under qemu-user (binfmt registered):
# big-endian (s390x, ppc64, mips) and ARM. -short skips the timing tests,
# which measure the emulator rather than the code.
EMULATED := s390x ppc64 mips arm arm64
emulated:
	@set -e; for arch in $(EMULATED); do echo "== $$arch"; \
		GOARCH=$$arch go test $(TAGS) -short -count=1 ./...; done

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
