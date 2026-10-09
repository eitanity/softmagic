# Security

## Reporting a vulnerability

Report privately through GitHub: the repository's **Security** tab, **Report a vulnerability**.
Please do not open a public issue for a vulnerability. Include the input that triggers it (or
how to build it), the call and `Options` used, and the version from `go.mod`.

## Supported versions

softmagic is pre-1.0. Fixes go into the latest minor release only; there are no backports.

| Version | Supported |
|---------|-----------|
| 0.3.x   | yes       |
| < 0.3   | no        |

## What softmagic trusts

| Input | Trust | Why |
|-------|-------|-----|
| The bytes being identified (`Identify*` data, an `io.ReaderAt`) | untrusted | the reason the library exists; every per-file cost is limited |
| Magic rules (`compile.Compile`, `CompileSources`, `Join`) | trusted, like code | rules choose the answer for every file |
| A compiled database (`Load`, `LoadEager`) | trusted, like code | `Load` checks the format and structure, not where the bytes came from |
| The embedded database (`Default`) | trusted | built from the vendored `file` 5.48 Magdir in this repository |

A rule can only read the input and write the answer: it cannot open a file, start a process or
use the network. The library itself has no `unsafe`, cgo, `os/exec` or network code, and links
no module outside the standard library.

## Using softmagic on untrusted input

**The description contains text from the input.** A rule may print a string it read from the
file (a title, a name, a version). Non-printable bytes are written as `\ooo` escapes unless
`Options.Raw` is set, so control characters and terminal escapes do not survive, but printable
characters do: `<script>`, quotes or a convincing type name are passed through unchanged, as
`file` passes them. Encode `Description` and the `Continued` lists for wherever they go: HTML,
SQL, a shell command, a log line, a spreadsheet cell. Do not set `Options.Raw` for untrusted
input.

**The answer is not an allow-list on its own.** softmagic gives the answer `file` 5.48 gives.
The first strong match wins, and only the first `Options.MaxBytes` (7 MiB by default) are
consulted, so a file can be built to be two things at once or to hide content past the window.
Use the answer to route a file, not to admit it. When a decision depends on it:

- check `Result.Examined.Truncated`: when it is set, a limit or the deadline cut the match
  short and the answer may be incomplete;
- check `Result.Failures`: a limit that is an error in `file` (indirect, name, ELF note size)
  is reported there;
- confirm the type with a parser for that format before trusting the content.

**Give every call a deadline.** `Identify(data)` has no deadline. For untrusted input call
`IdentifyWith` or `IdentifyAt` with a context that has one; when it expires the match stops
between rule steps and `Examined.Truncated` is `"time"`. Each rule step is itself bounded by
the limits below.

**Bound concurrency.** A `Database` is safe for concurrent use. Each call in flight holds a
pooled scan whose buffers grow to what the call needs and are kept for reuse: up to the
`MaxBytes` window plus about six times the encoding window (384 KiB at the default 64 KiB).
Limit the number of calls in flight to bound memory.

**A `ReaderAt` can stall a call.** `IdentifyAt` reads through the caller's `io.ReaderAt`, and a
read already in progress is not interrupted by the context. Give the reader its own timeout if
it can block.

**A panic is a defect and is not recovered.** The release build has no deliberate panic: a
panic means a bounds check in softmagic is wrong, and it is left to surface with its stack
rather than be turned into an answer. Please report it with the input. A caller that must keep
serving may recover around the call itself; it should then use an eager database
(`DefaultEager`, `LoadEager` or `compile.Compile`), which has no lazily built state for an
interrupted call to leave behind.

## Limits

These are `file`'s limits, with its defaults. `Options.Limits` and `Options.MaxBytes` change
them; zero means the default.

| Limit | Default |
|-------|---------|
| bytes consulted (`MaxBytes`) | 7 MiB |
| indirect offsets per match | 50 |
| nested `use` (`name`) | 150 |
| `use`/`indirect` frames | 32 |
| regex region | 8192 bytes |
| encoding window | 64 KiB |
| ELF program headers, sections, notes, note size | `file` 5.48's values |
| answer length | 4096 bytes |

## Dependencies

`go.mod` requires the linters and vulnerability scanner that `make lint` runs, as `tool`
dependencies. None of them is linked into the library or a program that uses it: `go version -m`
on such a binary lists `github.com/eitanity/softmagic` as its only dependency. They do appear in
a consumer's module graph (`go list -m all`).

## How the code is checked

`make test` runs every test with assertions on and the race detector. `make lint` runs `go vet`,
staticcheck, govulncheck, gosec and golangci-lint. Fuzzers cover identification from a slice and
from a reader (`FuzzIdentify`, `FuzzIdentifyAt`), the rule compiler with joined and reloaded
databases (`FuzzCompile`), and the compiled-database decoder (`FuzzLoad`).
