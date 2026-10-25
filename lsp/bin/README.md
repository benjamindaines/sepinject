# Bundled secilc (static)

`secilc` here is a **statically linked** build of secilc 3.11 with libsepol 3.11 compiled in. It has no runtime
dependency on the system libsepol, so it is immune to the secilc↔libsepol version drift that otherwise causes
intermittent failures across machines.

The LSP server prefers this binary (see `_find_secilc` in `../sepolicy_lsp.py`): the search order is
`--secilc <path>`, then `$SEPOLICY_LSP_SECILC`, then this file, then `secilc` on `PATH`.

## Provenance

- secilc: 3.11 (SELinuxProject release)
- libsepol: 3.11 (statically linked in)
- target: `x86_64` Linux, static glibc (`file` reports "statically linked")
- sha256: `42161cf330bf7175e77e97d545fdedb6793e3290ec153dbf057e27824de79b81`
- policy versions supported by this build: up to 35 (the LSP passes `-c 30` by default for the MediaTek target)

secilc 3.11 has **no `--check` flag**; a check is a normal compile whose exit status is inspected. The LSP
invokes it as the project's `sepcheck.sh` Pass 1 does:

```
secilc -M true -G -N -c <policyvers> <base CILs...> <buffer.cil> -o <tmp> -f /dev/null
```

## Rebuilding (on TARDIS / Manjaro)

A native rebuild is preferable to trusting a cross-built binary. flex is in the Manjaro repos
(`pacman -S flex`), so the AUR `secilc`/`libsepol` source trees committed at the repo root are all that is
otherwise needed. See `build-secilc.sh` in this directory; point it at the extracted 3.11 source trees:

```
./build-secilc.sh /path/to/libsepol-3.11 /path/to/secilc-3.11 ./secilc
```

The architecture must match the machine that will run the LSP. A non-x86_64 host should rebuild rather than
use the bundled binary; if the bundled binary cannot execute, the secilc check degrades to a no-op and nothing
else is affected.
