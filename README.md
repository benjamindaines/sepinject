```
usage: sepinject.py [-h] [--te RULES.te] [--remove-te REMOVE.te] [--seapp SEAPP.txt] [--remove-seapp REMOVE_SEAPP.txt]
                    [--file-contexts FILE_CTX.txt] [--property-contexts PROP_CTX.txt] [--service-contexts SVC_CTX.txt]
                    [--hwservice-contexts HWSVC_CTX.txt] [--policy POLICY_FILE [POLICY_FILE ...]] [--system-selinux DIR]
                    [--vendor-selinux DIR] [--rom-root DIR] [--dry-run] [--dump-json OUT.json] [--skip-binary] [--skip-cil] [--skip-seapp]
                    [--skip-file-contexts] [--skip-property-contexts] [--skip-service-contexts] [--skip-hwservice-contexts]
                    [--skip-sha256] [--skip-neverallow-check] [--plat-cil-only]

Inject SELinux policy rules from a .te file into Android ROM policy files.

options:
  -h, --help            show this help message and exit
  --te RULES.te         .te file with SELinux policy rules to ADD (allow, type, genfscon, typeattribute, ...)
  --remove-te REMOVE.te
                        .te file with rules to REMOVE from the policy. Same syntax as --te but each statement is prefixed with remove_:
                        remove_allow, remove_type, remove_genfscon, remove_permissive, remove_typeattribute
  --seapp SEAPP.txt     File with seapp_contexts lines to append to plat_seapp_contexts
  --remove-seapp REMOVE_SEAPP.txt
                        File with seapp_contexts lines to REMOVE from plat_seapp_contexts (exact line match). Run before --seapp to
                        replace stale entries.
  --file-contexts FILE_CTX.txt
                        File with file_contexts lines to append to plat_file_contexts
  --property-contexts PROP_CTX.txt
                        File with property_contexts lines to append to plat_property_contexts (system) and/or vendor_property_contexts.
                        Format: "persist.foo.bar u:object_r:mytype:s0 exact string"
  --service-contexts SVC_CTX.txt
                        File with service_contexts lines to append to plat_service_contexts. Format: "my.service.name
                        u:object_r:my_service:s0"
  --hwservice-contexts HWSVC_CTX.txt
                        File with hwservice_contexts lines to append to plat_hwservice_contexts or vendor_hwservice_contexts. Format:
                        "vendor.foo@1.0::IFoo/default u:object_r:hal_foo_hwservice:s0"
  --policy POLICY_FILE [POLICY_FILE ...]
                        One or more binary sepolicy files to patch directly
  --system-selinux DIR  Path to system/etc/selinux directory (for CIL, seapp_contexts, file_contexts, sha256 update)
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
                        Skip the pre-flight CIL neverallow conflict scan. By default, the tool checks whether any --te allow rules
                        conflict with existing CIL neverallow rules and offers to rewrite them.
  --plat-cil-only       When running the neverallow conflict scan, only process plat_sepolicy.cil (the system partition CIL). By default
                        the scan also covers vendor_sepolicy.cil and system_ext_sepolicy.cil where present, matching the scope of binary
                        policy patching.

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
  type_transition, typeattribute, genfscon

Supported removal directives (--remove-te):
  Same syntax as --te but prefixed with remove_:
  remove_allow src tgt:cls { perms };
  remove_genfscon fs "/path";
  remove_permissive type;
  remove_type type;           (CIL only — binary type removal not supported)
  remove_typeattribute type attr;

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
