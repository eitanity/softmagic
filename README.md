# softmagic

`softmagic` is a pure-Go port of `file(1)`: given bytes, it returns the description, MIME type
and extension that `file` returns for the same bytes and the same magic database, with every
answer stating what it examined and what it did not, safe to call from any number of goroutines,
with a bounded cost per call that a crafted input cannot raise.

It is a port of `file(1)` by Ian F. Darwin and Christos Zoulas. The magic database in
`magic/Magdir` is copied unmodified from the `file` 5.48 release, and the files whose header says
so are translations of its C sources (`apprentice.c`, `softmagic.c`, `funcs.c`, `encoding.c`,
`ascmagic.c`, `print.c`, `file.h`). Both are redistributed under the two-clause BSD licence in
`COPYING`, whose conditions are: redistributions of source code must retain the copyright notice,
this list of conditions and the disclaimer; redistributions in binary form must reproduce them in
the documentation or other materials provided with the distribution. The Go code is Copyright (c)
2026 Eitanity Systems VCC under the BSD-2-Clause licence in `LICENSE`.

This module is a library only. The command-line tool is the separate module
`github.com/eitanity/softmagic-cli`.

## Use

```go
db, err := softmagic.Default() // the embedded database; load once, keep it
if err != nil {
    log.Fatal(err)
}
// or, for your own rules: compile.Compile(os.DirFS(dir), softmagic.CompileOptions{})
r := db.Identify(data)
fmt.Println(r.Description, r.MIME, r.Charset, r.Extensions)
fmt.Println(r.Examined.Bytes, r.Examined.Truncated, r.Examined.DatabaseHash)
```

`IdentifyWith` takes a `context.Context` (its deadline ends the match with `Truncated: "time"`)
and `Options` (`MaxBytes`, default 7 MiB as in file 5.48; `MaxDepth` for `use`/`indirect`
nesting; `Executable`, the file's permission bit). `IdentifyAt` takes an `io.ReaderAt` and the
input's size, so the ELF built-in can read headers past the window as `file(1)` does; it is what
a CLI should call for a file. `IdentifyPrefix` identifies a prefix and says in
`Examined.NeedMore` whether more bytes could change the answer. `List()` prints the database in
matching order in the format of `file -l`. A `Result` is never blank: an unmatched input is
`data` / `application/octet-stream`.

`Options.Continue` is libmagic's `MAGIC_CONTINUE`, `file -k`: `Result.Continued` then holds
every match, as one list per output mode (descriptions, MIME types, encodings, extensions,
Apple codes). The reference computes each mode in a run of its own, so the lists are
independent: element *i* of one is not about the same entry as element *i* of another. Each
list joined with `"\\012- "` is byte-identical to `file -b -k` in that mode (with `Raw`, joined
with `"\n- "`, to `file -b -k -r`), and the rest of the
`Result` is what it is without the option. A continue call does the work of five runs and
costs about five times a first-match call: median 0.26 ms against 0.03 ms on the corpus, max
1.1 ms. `Options.Raw` is `MAGIC_RAW`, `file -r`: the answer is returned as it was printed.
Without it, every answer goes through the reference's output escaping, as libmagic's
`magic_buffer` returns it: a character glibc's `iswprint` rejects in a UTF-8 locale (a control
byte a `%c` rule copied from the input, say) is written as the `\ooo` escapes of its bytes, and
an answer that is not valid UTF-8 has every byte outside printable ASCII escaped. The table of
printable characters is generated from glibc (`make wctype`). `Failure` buffers are not escaped,
as `file` prints its errors.

`Options.SafeText` is not in the reference: it gives an answer safe to put into HTML, a log line
or a quoted value as it is. Every byte copied from the input (a `%s` string or match, a `%c`
byte, an ELF interpreter or note string, a CDF property or catalog name) is written as `\xHH`
unless it is printable ASCII other than `\ < > & " '` and the backquote, so text from the file
can neither open markup nor end a quoted value, and each backslash from the file starts an
escape, which makes the text decode exactly. Every answer and failure buffer is then printable
ASCII. The rules' own text and the classification are unchanged; it overrides `Raw`.

`Options.Exclude` is `MAGIC_NO_CHECK_*`, `file -e`: `CheckSoft`, `CheckText`, `CheckEncoding`,
`CheckTar`, `CheckJSON`, `CheckCSV`, `CheckSIMH`, `CheckCDF`, `CheckELF` switch those checks off
(`CheckCompress`, `CheckAppType` and `CheckTokens` are accepted and change nothing, as in the
reference). `Options.Limits` is libmagic's other parameters, `file -P`: indirect count, `use`
nesting, regex bytes, encoding bytes and the ELF note, program-header, section and note-size
limits; zero is `file`'s default and a negative value is its 0 (likewise `MaxBytes`, so
`MaxBytes: -1` is `bytes=0`). Three limits are errors in the reference when reached: indirect,
name and ELF note size. The library still returns an answer, with `Examined.Truncated` naming
the limit, and `Result.Failures` carries for each output mode the error libmagic would report;
`Failure.Text` is what `file` prints after `ERROR: `.

`softmagic.DumpSources` and `compile.Dump` are `file -c`: each rule line, in the order read, in
libmagic's parsed form (`*unknown*, 14: > 0 string,=@abstract:,"A2ML ..."]`), byte-identical to
what `file -c` prints for the same directory.

The compiled form (`Marshal`, `Load`) carries a format version, the `file` release it was
compiled for and the source hash; `Load` refuses another version or release by name. After
`Load` or `Default`, regexes compile on first use behind one `sync.Once` per rule, which keeps
the load near a millisecond. `DefaultEager` and `LoadEager` compile all of them before
returning (1.5 ms for Magdir): nothing lazy remains, no allocation follows initialisation, and
the matcher never touches a `sync.Once`. A database from `compile.Compile` is always eager,
since compilation validates every pattern anyway, and a `Join` of two eager databases stays
eager.

Two packages. `softmagic` loads, identifies, lists and marshals; `softmagic/compile` reads a
rule directory, hashes it and builds a database (`compile.Compile`, `compile.Append`). The
split is for the linker: a program that only loads the embedded database, the common case,
imports `softmagic` alone and carries neither the hashing nor its package initialiser, nor the
regex parser beyond what `regexp` itself needs; measured on a minimal load-and-identify
program, 172 KB less in a stripped binary, with no `crypto` symbol left. Rules already in
memory can go straight to `softmagic.CompileSources`, which takes the sources and the hash to
record.

A caller's own rules extend the embedded database as `file -m` extends the reference's:
compile them with `CompileOptions{Base: base}` so their `use` lines may name the
base's entries, then `compile.Append(base, extra)` (or `base.Join(extra, hash)` with a hash of
the caller's choosing). Each source keeps its own sort and the base is searched first, as the
reference searches `-m a:b`; the joined database reports a hash over both, and `Marshal` writes
it as one file. `Result.Apple` is the first `!:apple` annotation on the winning path, what
`file --apple` prints.

`CompileOptions.SourceDir` is the directory name the reference was given on its command line
(`file -m <dir>`); the reference writes `<dir>/<file>` into every empty description and its
ordering tie-break compares those bytes, so the port needs the same name to reproduce the same
order. The default, `magic/Magdir`, is what the listing oracle was taken with.

## Safety

No `unsafe`, cgo, `os/exec`, network or third-party module in the build: every requirement in
`go.mod` is there for a `tool` directive (the linters and govulncheck), and none is linked into
the library or a program that uses it. `SECURITY.md` describes what the library trusts and how
to use it on untrusted input. The compiled database is immutable; all per-call state is a
pooled `scan` struct of fixed-size arrays. Every limit that fires is reported in
`Examined.Truncated`. The module's own code follows Holzmann's Power of Ten: no recursion (the
reference's recursive `use`/`indirect` evaluation runs on an explicit frame stack), only counted
loops, one assertion primitive (`internal/invariant`) that panics in tests and in release
returns the failed condition to its caller, which handles it, functions under a page, no package-level mutable state, checked integer
conversions, one build tag, no function values or double indirection, and zero warnings from
every tool. `internal/rules` is the test that checks what the linters cannot.

## Verification

```
make test     # go test -tags softmagic_assert -race ./...
make lint     # vet, staticcheck, govulncheck, gosec, golangci-lint
make fuzz     # FuzzCompile for FUZZTIME (default 30s)
make generate # rebuild magic/softmagic.db from magic/Magdir (TestEmbeddedCurrent fails if stale)
make wctype   # regenerate wctype.go, the iswprint table, from this host's glibc (C.UTF-8)
go test -tags softmagic_assert -run NONE -fuzz FuzzIdentify -fuzztime 60s .
go test -run TestLatencyReport -v .
```

Every test runs under `-tags softmagic_assert`, which makes a failed invariant panic. The parity
corpus and its expected outputs are described in `testdata/corpus/SOURCES.md`; the reference
listing is `testdata/file-5.48-list.txt`. Both came from `file` 5.48 built from the signed
release tarball (`magic/README.md`).

## Updating the database

A `file` release is one commit: verify the tarball's signature, diff the grammar in
`apprentice.c`, `softmagic.c` and `file.h` against the implemented release, vendor `Magdir`
and `COPYING`, regenerate the expected listing and corpus outputs with the reference built from
the same tarball, and bump `ImplementsFile`. A database newer than `ImplementsFile` is refused.
