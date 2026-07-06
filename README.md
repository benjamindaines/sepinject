### NOTE:
It is recommended to run SEPcheck before making any changes, to make sure the .cil files in your ROM actually compile.  It's fairly likely that they won't.  If they don't, run SEPsani to clean them of duplicate entires across multiple partitions.  Run SEPcheck again after, it should pass at that point.. hopefully. 

This toolset has only been tested during the process of building the BenOS ROM, I assume it will work generally, let me know if it doesn't or feel free to fork and submit PRs with changes that make it work more universally.

Good luck, have fun.  Make frequent backups. 

# SEPinject
```
usage: SEPinject [-h] [--te RULES.te] [--remove-te REMOVE.te] [--seapp SEAPP.txt]
                 [--remove-seapp REMOVE_SEAPP.txt] [--file-contexts FILE_CTX.txt]
                 [--property-contexts PROP_CTX.txt] [--service-contexts SVC_CTX.txt]
                 [--hwservice-contexts HWSVC_CTX.txt] [--policy POLICY_FILE [POLICY_FILE ...]]
                 [--system-selinux DIR] [--vendor-selinux DIR] [--rom-root DIR] [--dry-run]
                 [--dump-json OUT.json] [--skip-binary] [--skip-cil] [--skip-seapp] [--skip-file-contexts]
                 [--skip-property-contexts] [--skip-service-contexts] [--skip-hwservice-contexts] [--skip-sha256]
                 [--skip-neverallow-check] [--plat-cil-only] [--no-auto-coredomain] [--coredomain TYPE]
                 [--vendor-attr-add ATTR=TYPE1,TYPE2] [--validate] [--validate-full] [--rebuild-neverallows]
                 [--rebuild-mods-marker MARKER] [--yes] [--recreate-mlsconstrains] [--recreate-mls-domain DOMAIN]
                 [--check-mlsconstrains]

Inject SELinux policy rules from a .te file into Android ROM policy files.

options:
  -h, --help            show this help message and exit
  --te RULES.te         .te file with SELinux policy rules to ADD (allow, type, genfscon, typeattribute, ...)
  --remove-te REMOVE.te
                        .te file with rules to REMOVE from the policy. Same syntax as --te but each statement is
                        prefixed with remove_: remove_allow, remove_type, remove_genfscon, remove_permissive,
                        remove_typeattribute
  --seapp SEAPP.txt     File with seapp_contexts lines to append to plat_seapp_contexts
  --remove-seapp REMOVE_SEAPP.txt
                        File with seapp_contexts lines to REMOVE from plat_seapp_contexts (exact line match). Run
                        before --seapp to replace stale entries.
  --file-contexts FILE_CTX.txt
                        File with file_contexts lines to append to plat_file_contexts
  --property-contexts PROP_CTX.txt
                        File with property_contexts lines to append to plat_property_contexts (system) and/or
                        vendor_property_contexts. Format: "persist.foo.bar u:object_r:mytype:s0 exact string"
  --service-contexts SVC_CTX.txt
                        File with service_contexts lines to append to plat_service_contexts. Format:
                        "my.service.name u:object_r:my_service:s0"
  --hwservice-contexts HWSVC_CTX.txt
                        File with hwservice_contexts lines to append to plat_hwservice_contexts or
                        vendor_hwservice_contexts. Format: "vendor.foo@1.0::IFoo/default
                        u:object_r:hal_foo_hwservice:s0"
  --policy POLICY_FILE [POLICY_FILE ...]
                        One or more binary sepolicy files to patch directly
  --system-selinux DIR  Path to system/etc/selinux directory (for CIL, seapp_contexts, file_contexts, sha256
                        update)
  --vendor-selinux DIR  Path to vendor/etc/selinux directory (for vendor sidecar sha256 update)
  --rom-root DIR        Root of an unpacked ROM; auto-discovers all targets
  --dry-run             Show what would be done without writing any files
  --dump-json OUT.json  Write parsed binary-patch rules to a JSON file
  --skip-binary         Skip binary sepolicy patching (CIL/context only)
  --skip-cil            Skip plat_sepolicy.cil patching
  --skip-seapp          Skip plat_seapp_contexts patching
  --skip-file-contexts  Skip plat_file_contexts patching
  --skip-property-contexts
                        Skip property_contexts patching
  --skip-service-contexts
                        Skip service_contexts patching
  --skip-hwservice-contexts
                        Skip hwservice_contexts patching
  --skip-sha256         Skip SHA-256 recomputation
  --skip-neverallow-check
                        Skip the pre-flight CIL neverallow conflict scan. By default, the tool checks whether any
                        --te allow rules conflict with existing CIL neverallow rules and offers to rewrite them.
  --plat-cil-only       When running the neverallow conflict scan, only process plat_sepolicy.cil (the system
                        partition CIL). By default the scan also covers vendor_sepolicy.cil and
                        system_ext_sepolicy.cil where present, matching the scope of binary policy patching.
  --no-auto-coredomain  Disable automatic coredomain attribution for new domains. By default, any type declared
                        as a domain (or targeted by a process-class type_transition) is automatically added to
                        the coredomain typeattributeset in plat_sepolicy.cil. This is required to satisfy Treble
                        plat-vs-vendor neverallows for new plat-side domains. Disable only if you know what you
                        are doing.
  --coredomain TYPE     Explicitly add this type name to the coredomain typeattributeset in plat_sepolicy.cil.
                        Can be passed multiple times. Useful when --no-auto-coredomain is set, or when you want
                        to add a type to coredomain without declaring it via --te.
  --vendor-attr-add ATTR=TYPE1,TYPE2
                        Augment a typeattributeset in vendor_sepolicy.cil. Format: --vendor-attr-add
                        ATTR=TYPE1,TYPE2. The specified types are added to the named attribute set in vendor's
                        CIL without re-declaring the types (which would cause a duplicate-declaration compile
                        error). Use this when a new plat-side type needs membership in a vendor-defined attribute
                        set.
  --validate            Run policy validation in surgical mode: scan all CIL files under --rom-root for broken
                        sepinject artifacts (nested aux refs, dangling aux references, orphaned/empty/duplicate
                        aux decls, unrecoverable blocks) and offer to repair each one by rebuilding from the
                        audit-trail baseline. Standalone mode only — must be combined with --rom-root; combinable
                        with --dry-run for a no-op preview. Backs up every touched CIL file to <rom-
                        root>/sepinject_validate_backup_<TS>/ before making any change (skipped under --dry-run).
  --validate-full       Like --validate, but rebuild EVERY sepinject rewrite block in every targeted CIL file
                        from baseline — even ones that currently look well-formed. Use this when the policy is
                        badly corrupted and a from-scratch rebuild is preferable to per-issue surgery. Implies
                        --validate.
  --rebuild-neverallows
                        Recovery mode: scan the same fixed set of CIL files the normal pre-flight check already
                        targets under --rom-root (plat_sepolicy.cil, system_ext_sepolicy.cil,
                        vendor_sepolicy.cil, and plat_pub_versioned.cil — NOT a recursive glob), look for the
                        marker line '; ~~~:BEGIN_MODS:~~~', extract every `(allow ...)` rule below the marker,
                        and re-run the pre-flight neverallow conflict check against the FULL set of neverallows
                        in those CIL files. Conflicts are rewritten via the same carve-out / perm-drop machinery
                        used by the normal patch flow. Standalone — requires --rom-root, accepts --dry-run /
                        --skip-sha256 / --plat-cil-only / --yes. Backs up every targeted CIL into <rom-
                        root>/sepinject_rebuild_neverallows_backup_<TS>/ before any write. Assumes the user has
                        already manually removed prior sepinject_aux_* rewrites and restored the original
                        commented neverallow lines as live statements.
  --rebuild-mods-marker MARKER
                        Override the marker line used by --rebuild-neverallows to find the start of user mods
                        (default: '; ~~~:BEGIN_MODS:~~~')
  --yes, --assume-yes   Auto-approve the interactive prompt issued by --rebuild-neverallows / --recreate-
                        mlsconstrains (and the --check-mlsconstrains pre-flight). Use with care — in recovery
                        scenarios you may want to review each rewrite first.
  --recreate-mlsconstrains
                        Recovery mode, the MLS analogue of --rebuild-neverallows: scan the same fixed set of CIL
                        files under --rom-root (plat_sepolicy.cil, system_ext_sepolicy.cil, vendor_sepolicy.cil,
                        plat_pub_versioned.cil — NOT a recursive glob), look for the marker line ';
                        ~~~:BEGIN_MODS:~~~', extract every `(allow ...)` below it, and check those against the
                        FULL set of mlsconstrains. A constraint that would (or could) DENY a mod allow at runtime
                        is widened with an `(or ORIG (eq t1 sepinject_mlsaux_*))` exemption for the offending
                        subject domain(s). Standalone — requires --rom-root, accepts --dry-run / --skip-sha256 /
                        --plat-cil-only / --yes and the shared --rebuild-mods-marker. Backs up every targeted CIL
                        into <rom-root>/sepinject_recreate_mlsconstrains_backup_<TS>/ before any write.
  --recreate-mls-domain DOMAIN
                        Like --recreate-mlsconstrains, but only widen constraints that block the single source
                        domain DOMAIN — the mod allow rules are filtered to rule.src == DOMAIN before the scan.
                        Use this to exempt one domain at a time instead of punching holes in every constraint for
                        every mod subject at once. Same standalone requirements/flags as --recreate-
                        mlsconstrains.
  --check-mlsconstrains
                        During a normal --te patch run, ALSO scan for mlsconstrain conflicts (constraints that
                        would deny an injected allow at runtime) and offer to widen them, mirroring the
                        neverallow pre-flight. This is OPT-IN (the neverallow pre-flight is opt-out) on purpose:
                        unlike neverallow conflicts, mlsconstrain conflicts do NOT break a CIL recompile, so
                        auto-relaxing MLS on every run would silently loosen policy. Enable it only when you
                        specifically want MLS constraints considered.

sepinject.py — Inject or remove SELinux policy rules from pre-compiled
Android ROM binary policy files (sepolicy / precompiled_sepolicy) without
recompiling from source.

Supports patching:
  • vendor_boot/cpio_tree/sepolicy
  • vendor/fs_tree/etc/selinux/precompiled_sepolicy
  • system/fs_tree/system/etc/selinux/precompiled_sepolicy  (if present)

Supported .te rule types (--te, adding rules):
  allow, auditallow, dontaudit, neverallow (skipped with warning),
  permissive, type (declaration), attribute (declaration),
  type_transition, typeattribute, genfscon,
  mlstrustedsubject, mlstrustedobject (CIL-only sugar for
    `typeattribute X mlstrustedsubject;` — accepts one or more
    type names: `mlstrustedsubject foo, bar;`)

AOSP m4 macro expansion:
  Function-style te_macros (init_daemon_domain, domain_auto_trans,
  set_prop, get_prop, binder_use, binder_call, binder_service,
  unix_socket_connect) are expanded textually before parsing.

  AOSP global_macros — permission groupings (rx_file_perms, r_file_perms,
  w_file_perms, ra_file_perms, rw_file_perms, rwx_file_perms,
  create_file_perms, r_dir_perms, w_dir_perms, ra_dir_perms, rw_dir_perms,
  create_dir_perms, r_ipc_perms, w_ipc_perms, rw_ipc_perms,
  create_ipc_perms, rw_socket_perms, rw_socket_perms_no_ioctl,
  create_socket_perms, create_socket_perms_no_ioctl,
  rw_stream_socket_perms, create_stream_socket_perms) and class groupings
  (capability_class_set, file_class_set, devfile_class_set,
  notdevfile_class_set, dir_file_class_set, dgram_socket_class_set,
  stream_socket_class_set, unpriv_socket_class_set,
  network_socket_class_set, ipc_class_set, plus the global_capability*
  variants) — are flattened into their concrete perm/class sets, with
  recursive expansion (rx_file_perms -> r_file_perms x_file_perms ->
  final perms).  Both bare usage and usage inside brace groups work.

Supported removal directives (--remove-te):
  Same syntax as --te but prefixed with remove_:
  remove_allow src tgt:cls { perms };
  remove_genfscon fs "/path";
  remove_permissive type;
  remove_type type;           (CIL only — binary type removal not supported)
  remove_typeattribute type attr;
  remove_mlstrustedsubject type[, type ...];   (CIL only)
  remove_mlstrustedobject type[, type ...];    (CIL only)

Usage:
  # Add rules only
  python3 sepinject.py --te rules.te --rom-root /path/to/rom

  # Remove rules only
  python3 sepinject.py --remove-te remove.te --rom-root /path/to/rom

  # Remove old rules then add new ones (safe replace pattern)
  python3 sepinject.py --remove-te old_rules.te --te new_rules.te --rom-root /path/to/rom

  # Dry run to preview changes
  python3 sepinject.py --te rules.te --remove-te remove.te --dry-run

The tool compiles a small C helper (sepatch_helper) against the system
libsepol on first run and caches it at ~/.cache/sepinject/sepatch_helper.
```
# SEPclean
```
usage: SEPclean [-h] [-o OUTPUT] [--relocate-neverallows] [--relocate-mlsconstrains] [--dry-run] [--force] input

Clean & regroup a sepinject CIL.

positional arguments:
  input

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   write cleaned output here and do NOT rename input (default: rename input to
                        <input>.unclean and write the cleaned result under the input's original name)
  --relocate-neverallows
                        pull active rewritten neverallows from above the marker down into the mods region
  --relocate-mlsconstrains
                        pull active rewritten mlsconstrains (those carrying a sepinject_mlsaux_ exemption) from
                        above the marker down into the mods region
  --dry-run             validate and report, but write nothing
  --force               allow overwriting an existing <input>.unclean
```
# SEPsani
```
usage: SEPsani [-h] [--plat PLAT] [--ppv PPV] [--vendor VENDOR] [--system-ext SYSTEM_EXT] [--dry-run] [rom_root]

sanitize_cil.py

Clean up ROM-shipped CIL files so they can be re-compiled by secilc.

Background
----------
This ROM's CIL files contain structural duplicates that prevent fresh
compilation by secilc.  The precompiled_sepolicy binary was produced by
Google's build pipeline (which uses custom CIL combiner tooling that
handles these duplicates) — but `secilc` on Ubuntu/Linux refuses them.

The duplicates appear to fall into a few specific categories:

  (1) Same `(type X)` declared in both plat_sepolicy.cil and
      plat_pub_versioned.cil.  The ppv file is supposed to hold only
      VERSIONED types (like adbd_31_0), but here it also redeclares
      UNVERSIONED ones that plat owns.  Solution: remove duplicates
      from ppv, since plat is the canonical owner.

  (2) Same `(typeattribute X)` declared in both files.  Same fix.

  (3) Within plat_sepolicy.cil itself, `system_and_vendor_property_type`
      is declared twice.  The second occurrence is part of an explicit
      "workaround" block — but the type was already auto-declared earlier.
      Solution: comment out the second occurrence.

  (4) A handful of `(type X)` duplicates between plat and vendor_sepolicy.cil
      (e.g. `proc_cpu_alignment`).  These are vendor types that plat
      somehow also declares.  Solution: comment them out of vendor since
      plat owns them at the platform layer.

  (5) Some `(typeattributeset X ...)` lines may also conflict, especially
      if both files claim the same attribute as a complex S-expression.
      Solution: detect at compile time, address case by case.

Usage
-----
    python3 sanitize_cil.py /path/to/rom/

Where /path/to/rom/ is the directory containing system/, vendor/, and
system_ext/ subtrees.  The script will locate the CIL files itself.

Or pass paths explicitly:

    python3 sanitize_cil.py         --plat /path/.../plat_sepolicy.cil         --ppv /path/.../plat_pub_versioned.cil         --vendor /path/.../vendor_sepolicy.cil         --system-ext /path/.../system_ext_sepolicy.cil

A `.before_sanitize.bak` backup is made of each file before modification
(skipped if a backup already exists).  All removals are by COMMENTING
OUT the offending lines with a `; sanitize:` marker — never destructive.
Re-running is idempotent.

After running, you'll want to verify with secilc:

    secilc -M true -G -N -c 30 \
        plat_sepolicy.cil system_ext_sepolicy.cil \
        vendor_sepolicy.cil plat_pub_versioned.cil \
        -o /tmp/check.bin

If new errors surface, address them and re-run.

positional arguments:
  rom_root              ROM root containing system/, vendor/, system_ext/

options:
  -h, --help            show this help message and exit
  --plat PLAT           Path to plat_sepolicy.cil
  --ppv PPV             Path to plat_pub_versioned.cil
  --vendor VENDOR       Path to vendor_sepolicy.cil
  --system-ext SYSTEM_EXT
                        Path to system_ext_sepolicy.cil
  --dry-run             Report what would change without writing
```
# SEPcheck
Nothing fancy, just a bash script that calls secilc.  Installer script places it in ~/.local/bin/ along with the other binaries.  Edit the file in this directory and re-run install.sh, or edit SEPcheck in ~/.local/bin/ with the relevant directory paths for your env.

# SEPwalk
Feed it your .te file and --rom-root and it will suggest additional rules you will need.  Not perfect, does help tho.  This is the major area that could use improvement. 
```
usage: sepolwalker [-h] --te TE --rom-root ROM_ROOT [-o OUTPUT] [-v]

Walk an Android SELinux policy to find prerequisite rules required to make a
given .te file work.

options:
  -h, --help           show this help message and exit
  --te TE              The .te source file describing the rules you want.
  --rom-root ROM_ROOT  Root of an extracted ROM (must contain system/fs_tree/,
                       vendor/fs_tree/, system_ext/fs_tree/).
  -o, --output OUTPUT  Write the report to this file instead of stdout.
  -v, --verbose        Print extra progress info to stderr.
```
