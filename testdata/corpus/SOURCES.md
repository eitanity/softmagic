# Parity corpus

Every `*.testfile` here is copied unmodified from `tests/` of the `file` 5.48
release (see `magic/README.md` for the tarball's hash and signature), under
the licence in `COPYING` at the module root. The matching `*.expect` files
hold four lines, produced by the reference built from that tarball with
`TZ=UTC` and `-m magic/Magdir`:

1. `file -b`
2. `file -b -i`
3. `file -b --extension`
4. `file -b --apple`

Third-party samples added later carry their own terms and are listed here
with their origin, or they are not committed.

The `sample-*.testfile` entries are not from the reference's `tests/`: they were made for this
module on 2026-10-03 (GNU tar 1.35 in its gnu, posix and v7 formats over two tiny text files; two
hand-written CSV files; a SIMH tape image written by a six-line Python script) and carry the
module's `LICENSE`. Their `.expect` files were produced the same way as the others.

`sample-elf-*` and `sample-elf32-static` were built here from a four-line C file with
`gcc -nostdlib` (static, static stripped, shared, pie, non-pie, relocatable, and 32-bit static);
`sample-word97-doc` and `sample-excel97-xls` were written by LibreOffice 25.x from a two-line text
file and a two-line CSV; `sample-x509-der` is a self-signed certificate from `openssl req`. All
under the module's `LICENSE`, expectations from the reference as above.
