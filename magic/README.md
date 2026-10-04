# magic/Magdir

The magic database of `file` 5.48, vendored verbatim from the release tarball.

| | |
|---|---|
| release | `file-5.48.tar.gz`, 2026-06-07 |
| source | https://astron.com/pub/file/file-5.48.tar.gz |
| SHA-256 | `ed14656883b23a364b4057c05595d93252da9bc473d30106519519d0da141283` |
| signature | `file-5.48.tar.gz.asc`, DSA key `BE04 995B A8F9 0ED0 C0C1 76C4 7111 2AB1 6CB3 3B3A` (Christos Zoulas); good signature verified 2026-10-03 — the key itself is past its expiry date |
| files | 356 |
| licence | `COPYING` at the module root, the reference's own notice |

Do not edit these files. A database update follows a new `file` release, never upstream
`master`, and is one commit:

1. **Acquire and verify.** Fetch the release tarball and its detached signature from
   `astron.com/pub/file/`, verify the signature, confirm the release tag on
   `github.com/file/file` matches the tarball, and record both hashes in the table above.
2. **Diff the grammar before the data.** Diff `src/apprentice.c`, `softmagic.c`, `file.h`,
   `funcs.c` and `ascmagic.c` between the two release tags, looking for new or removed
   `FILE_*` types, changes to the strength function (`apprentice_magic_strength_1`,
   `file_magic_strength`), to `apprentice_sort` or to `struct magic`'s field order (both
   decide which entry answers), new string flags, and changes to text classification or
   output formatting. Port and test each one first, and bump `ImplementsFile`. A type the
   port does not implement is a compile error naming the Magdir line.
3. **Vendor** the release's `magic/Magdir` here verbatim and refresh `COPYING`.
4. **Compile**: `make generate` rewrites `magic/softmagic.db`; it must compile with no
   skipped lines.
5. **Gate** against a `file` built from the same verified tarball, not the host's package:
   the listing oracle (`testdata/file-<release>-list.txt`, from `file -m magic/Magdir -l`),
   the parity corpus including the release's own `tests/`, race, fuzz, bounds and
   benchmark. Classify every new divergence as a port bug (fix it), a `file` bug (report it
   upstream) or deliberate (document it) before merging.
6. **Record** `ImplementsFile`, the database hash, the parity figure and the divergences in
   the changelog entry. The library version bumps minor for new types or formats, patch for
   data only.
