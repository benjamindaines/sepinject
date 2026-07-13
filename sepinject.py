#!/usr/bin/env python3
"""
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
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# C helper source — compiled once, cached, used for every policy patch.
# Reads rules from a JSON file passed as argv[1] and patches policy argv[2].
# ---------------------------------------------------------------------------

HELPER_C_SOURCE = r"""
/*
 * sepatch_helper.c
 * Patches a binary SELinux policy using libsepol based on a JSON rule set.
 *
 * JSON schema (array of rule objects):
 *   {"op":"allow",        "src":"...", "tgt":"...", "cls":"...", "perms":["..."]}
 *   {"op":"auditallow",   "src":"...", "tgt":"...", "cls":"...", "perms":["..."]}
 *   {"op":"dontaudit",    "src":"...", "tgt":"...", "cls":"...", "perms":["..."]}
 *   {"op":"permissive",   "type":"..."}
 *   {"op":"type",         "name":"...","attr":"..."}   -- attr optional
 *   {"op":"attribute",    "name":"..."}
 *   {"op":"typeattribute","type":"...","attr":"..."}
 *   {"op":"type_transition","src":"...","tgt":"...","cls":"...","default":"...","name":"..."}  -- name optional
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sepol/handle.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/symtab.h>
#include <sepol/policydb/services.h>

/* ---- tiny JSON tokenizer ---- */
typedef struct { const char *s; size_t len; } Tok;

static int skip_ws(const char **p) { while(**p==' '||**p=='\t'||**p=='\n'||**p=='\r') (*p)++; return 0; }

static char *parse_string(const char **p) {
    skip_ws(p);
    if(**p != '"') return NULL;
    (*p)++;
    const char *start = *p;
    while(**p && **p != '"') {
        if(**p == '\\') (*p)++;
        (*p)++;
    }
    size_t len = *p - start;
    if(**p == '"') (*p)++;
    char *out = malloc(len+1);
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

/* ---- policy helpers ---- */

static sepol_handle_t *g_handle = NULL;

static void init_handle(void) {
    g_handle = sepol_handle_create();
    if(!g_handle) { fprintf(stderr, "sepol_handle_create failed\n"); exit(1); }
}

/* Load binary policy from file into policydb */
static int load_policy(const char *path, policydb_t *pdb) {
    FILE *f = fopen(path, "rb");
    if(!f) { fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc(sz);
    if(!buf) { fclose(f); fprintf(stderr, "OOM reading %s\n", path); return -1; }
    if((long)fread(buf, 1, sz, f) != sz) {
        free(buf); fclose(f);
        fprintf(stderr, "Read error on %s\n", path); return -1;
    }
    fclose(f);

    policy_file_t pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = buf;
    pf.len  = (size_t)sz;

    if(policydb_init(pdb) < 0) { free(buf); fprintf(stderr, "policydb_init failed\n"); return -1; }
    if(policydb_read(pdb, &pf, 0) < 0) {
        free(buf); policydb_destroy(pdb);
        fprintf(stderr, "policydb_read failed\n"); return -1;
    }
    free(buf);
    return 0;
}

/* Save policydb to file using policydb_to_image */
static int save_policy(const char *path, policydb_t *pdb) {
    void *data = NULL;
    size_t len = 0;
    if(policydb_to_image(g_handle, pdb, &data, &len) < 0) {
        fprintf(stderr, "policydb_to_image failed\n"); return -1;
    }

    FILE *f = fopen(path, "wb");
    if(!f) {
        fprintf(stderr, "Cannot write %s: %s\n", path, strerror(errno));
        free(data); return -1;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    free(data);
    return 0;
}

/* Lookup type/attr by name, optionally creating if missing */
static type_datum_t *get_or_create_type(policydb_t *pdb, const char *name, int is_attr, int create) {
    hashtab_datum_t d = hashtab_search(pdb->p_types.table, (hashtab_key_t)name);
    if(d) return (type_datum_t*)d;
    if(!create) return NULL;

    /* Create new type/attribute */
    type_datum_t *td = calloc(1, sizeof(type_datum_t));
    if(!td) { fprintf(stderr, "OOM\n"); exit(1); }
    type_datum_init(td);
    td->primary = 1;
    td->flavor = is_attr ? TYPE_ATTRIB : TYPE_TYPE;

    uint32_t id;
    char *name_copy = strdup(name);
    if(symtab_insert(pdb, SYM_TYPES, name_copy, td, SCOPE_DECL, 1, &id) != 0) {
        fprintf(stderr, "symtab_insert failed for type %s\n", name);
        free(td); free(name_copy); return NULL;
    }
    td->s.value = id;

    /* Extend val_to_struct arrays */
    pdb->p_type_val_to_name = realloc(pdb->p_type_val_to_name, sizeof(char*)*pdb->p_types.nprim);
    pdb->p_type_val_to_name[id-1] = name_copy;
    pdb->type_val_to_struct = realloc(pdb->type_val_to_struct, sizeof(type_datum_t*)*pdb->p_types.nprim);
    pdb->type_val_to_struct[id-1] = td;

    if(is_attr) {
        pdb->attr_type_map = realloc(pdb->attr_type_map, sizeof(ebitmap_t)*pdb->p_types.nprim);
        ebitmap_init(&pdb->attr_type_map[id-1]);
        pdb->type_attr_map = realloc(pdb->type_attr_map, sizeof(ebitmap_t)*pdb->p_types.nprim);
        ebitmap_init(&pdb->type_attr_map[id-1]);
    } else {
        /* For new types: resize and init bitmaps */
        pdb->type_attr_map = realloc(pdb->type_attr_map, sizeof(ebitmap_t)*pdb->p_types.nprim);
        ebitmap_init(&pdb->type_attr_map[id-1]);
        pdb->attr_type_map = realloc(pdb->attr_type_map, sizeof(ebitmap_t)*pdb->p_types.nprim);
        ebitmap_init(&pdb->attr_type_map[id-1]);
    }

    fprintf(stderr, "  [+] Created %s '%s' (id=%u)\n", is_attr?"attribute":"type", name, id);
    return td;
}

/* Apply typeattribute: add type to attribute's type_set ebitmap */
static int do_typeattribute(policydb_t *pdb, const char *type_name, const char *attr_name) {
    type_datum_t *type_d = get_or_create_type(pdb, type_name, 0, 0);
    if(!type_d) { fprintf(stderr, "  [!] Type '%s' not found\n", type_name); return -1; }
    type_datum_t *attr_d = get_or_create_type(pdb, attr_name, 1, 0);
    if(!attr_d) { fprintf(stderr, "  [!] Attribute '%s' not found\n", attr_name); return -1; }

    uint32_t type_idx = type_d->s.value - 1;
    uint32_t attr_idx = attr_d->s.value - 1;
    ebitmap_set_bit(&pdb->attr_type_map[attr_idx], type_idx, 1);
    ebitmap_set_bit(&pdb->type_attr_map[type_idx], attr_idx, 1);
    return 0;
}

/* Set permissive bit on a type */
static int do_permissive(policydb_t *pdb, const char *type_name) {
    type_datum_t *td = get_or_create_type(pdb, type_name, 0, 0);
    if(!td) { fprintf(stderr, "  [!] Type '%s' not found for permissive\n", type_name); return -1; }
    if(ebitmap_set_bit(&pdb->permissive_map, td->s.value, 1) < 0) {
        fprintf(stderr, "  [!] ebitmap_set_bit failed for permissive %s\n", type_name); return -1;
    }
    return 0;
}

/* Apply an AV rule (allow/auditallow/dontaudit) for one permission */
static int set_av_rule(policydb_t *pdb,
                       uint32_t src_val, uint32_t tgt_val,
                       uint32_t cls_val, uint32_t perm_bit,
                       int specified) {
    avtab_key_t key = {
        .source_type = (uint16_t)src_val,
        .target_type = (uint16_t)tgt_val,
        .target_class = (uint16_t)cls_val,
        .specified = (uint16_t)specified,
    };
    avtab_datum_t *d = avtab_search(&pdb->te_avtab, &key);
    if(!d) {
        avtab_datum_t datum = { .data = 0, .xperms = NULL };
        if(specified == AVTAB_AUDITDENY) datum.data = ~0U;
        int r = avtab_insert(&pdb->te_avtab, &key, &datum);
        if(r) { fprintf(stderr, "  [!] avtab_insert failed (%d)\n", r); return -1; }
        d = avtab_search(&pdb->te_avtab, &key);
    }
    if(specified == AVTAB_AUDITDENY)
        d->data &= ~(1U << (perm_bit-1));   /* clear bit = dontaudit */
    else
        d->data |= (1U << (perm_bit-1));
    return 0;
}

/* Apply allow/auditallow/dontaudit for all listed perms */
static int do_av_rule(policydb_t *pdb, const char *src, const char *tgt,
                      const char *cls, char **perms, int nperms, int specified) {
    /* Resolve src */
    int src_self = (strcmp(src, "self") == 0);
    type_datum_t *src_d = NULL;
    if(!src_self) {
        src_d = get_or_create_type(pdb, src, 0, 0);
        if(!src_d) { fprintf(stderr, "  [!] Source type '%s' not found\n", src); return -1; }
    }
    /* Resolve tgt */
    int tgt_self = (strcmp(tgt, "self") == 0);
    type_datum_t *tgt_d = NULL;
    if(!tgt_self) {
        tgt_d = get_or_create_type(pdb, tgt, 0, 0);
        if(!tgt_d) { fprintf(stderr, "  [!] Target type '%s' not found\n", tgt); return -1; }
    }
    /* Resolve class */
    hashtab_datum_t cls_dat = hashtab_search(pdb->p_classes.table, (hashtab_key_t)cls);
    if(!cls_dat) { fprintf(stderr, "  [!] Class '%s' not found\n", cls); return -1; }
    class_datum_t *cls_d = (class_datum_t*)cls_dat;

    uint32_t src_val = src_self ? 0 : src_d->s.value;
    uint32_t tgt_val = tgt_self ? src_val : tgt_d->s.value;
    if(tgt_self && src_self) { fprintf(stderr,"  [!] both src and tgt cannot be 'self'\n"); return -1; }

    for(int i = 0; i < nperms; i++) {
        const char *pname = perms[i];
        /* Look up in common perms first, then class perms */
        perm_datum_t *perm_d = NULL;
        if(cls_d->comdatum) {
            hashtab_datum_t pd = hashtab_search(cls_d->comdatum->permissions.table, (hashtab_key_t)pname);
            if(pd) perm_d = (perm_datum_t*)pd;
        }
        if(!perm_d) {
            hashtab_datum_t pd = hashtab_search(cls_d->permissions.table, (hashtab_key_t)pname);
            if(pd) perm_d = (perm_datum_t*)pd;
        }
        if(!perm_d) { fprintf(stderr, "  [!] Permission '%s' not found in class '%s'\n", pname, cls); continue; }

        if(set_av_rule(pdb, src_val, tgt_val, cls_d->s.value, perm_d->s.value, specified) < 0)
            return -1;
    }
    return 0;
}

/* Apply type_transition rule */
static int do_type_transition(policydb_t *pdb, const char *src, const char *tgt,
                               const char *cls, const char *def_type, const char *name) {
    type_datum_t *src_d = get_or_create_type(pdb, src, 0, 0);
    if(!src_d) { fprintf(stderr, "  [!] src type '%s' not found\n", src); return -1; }
    type_datum_t *tgt_d = get_or_create_type(pdb, tgt, 0, 0);
    if(!tgt_d) { fprintf(stderr, "  [!] tgt type '%s' not found\n", tgt); return -1; }
    type_datum_t *def_d = get_or_create_type(pdb, def_type, 0, 0);
    if(!def_d) { fprintf(stderr, "  [!] default type '%s' not found\n", def_type); return -1; }
    hashtab_datum_t cls_dat = hashtab_search(pdb->p_classes.table, (hashtab_key_t)cls);
    if(!cls_dat) { fprintf(stderr, "  [!] class '%s' not found\n", cls); return -1; }
    class_datum_t *cls_d = (class_datum_t*)cls_dat;

    if(name) {
        /* Named transition — stored in filename_trans hashtab if present */
        /* For older policies without filename_trans, fall back to plain transition */
        /* We use a filename_trans_datum if the policy supports it */
        /* For simplicity and compatibility we skip filename part for now */
        fprintf(stderr, "  [~] Named type_transition: name '%s' treated as plain transition\n", name);
    }

    avtab_key_t key = {
        .source_type = (uint16_t)src_d->s.value,
        .target_type = (uint16_t)tgt_d->s.value,
        .target_class = (uint16_t)cls_d->s.value,
        .specified = AVTAB_TRANSITION,
    };
    avtab_datum_t *d = avtab_search(&pdb->te_avtab, &key);
    if(!d) {
        avtab_datum_t datum = { .data = def_d->s.value, .xperms = NULL };
        if(avtab_insert(&pdb->te_avtab, &key, &datum) != 0) {
            fprintf(stderr, "  [!] avtab_insert (transition) failed\n"); return -1;
        }
    } else {
        d->data = def_d->s.value;
    }
    return 0;
}

/* Compute the same hash as libsepol's internal avtab_hash() */
static uint32_t avtab_hash_key(avtab_key_t *keyp, uint32_t mask) {
    return ((keyp->target_class + (keyp->target_type << 2) +
             (keyp->source_type << 9)) & mask);
}

/* Remove an AV rule entry by manually unlinking it from the hash bucket.
   libsepol has no public avtab_remove() — we replicate it here using the
   public struct layout from avtab.h. */
static int do_remove_av_rule(policydb_t *pdb, const char *src, const char *tgt,
                              const char *cls, char **perms, int nperms) {
    type_datum_t *src_d = get_or_create_type(pdb, src, 0, 0);
    if(!src_d) { fprintf(stderr, "  [~] remove_allow: src '%s' not found, skipping\n", src); return 0; }
    type_datum_t *tgt_d = get_or_create_type(pdb, tgt, 0, 0);
    if(!tgt_d) { fprintf(stderr, "  [~] remove_allow: tgt '%s' not found, skipping\n", tgt); return 0; }
    hashtab_datum_t cls_dat = hashtab_search(pdb->p_classes.table, (hashtab_key_t)cls);
    if(!cls_dat) { fprintf(stderr, "  [~] remove_allow: class '%s' not found, skipping\n", cls); return 0; }
    class_datum_t *cls_d = (class_datum_t*)cls_dat;

    avtab_key_t key = {
        .source_type = (uint16_t)src_d->s.value,
        .target_type = (uint16_t)tgt_d->s.value,
        .target_class = (uint16_t)cls_d->s.value,
        .specified = AVTAB_ALLOWED,
    };

    avtab_datum_t *d = avtab_search(&pdb->te_avtab, &key);
    if(!d) {
        fprintf(stderr, "  [~] remove_allow: no existing rule for %s %s:%s — skipping\n", src, tgt, cls);
        return 0;
    }

    /* Clear the requested permission bits */
    for(int i = 0; i < nperms; i++) {
        const char *pname = perms[i];
        perm_datum_t *perm_d = NULL;
        if(cls_d->comdatum) {
            hashtab_datum_t pd = hashtab_search(cls_d->comdatum->permissions.table, (hashtab_key_t)pname);
            if(pd) perm_d = (perm_datum_t*)pd;
        }
        if(!perm_d) {
            hashtab_datum_t pd = hashtab_search(cls_d->permissions.table, (hashtab_key_t)pname);
            if(pd) perm_d = (perm_datum_t*)pd;
        }
        if(!perm_d) {
            fprintf(stderr, "  [~] remove_allow: perm '%s' not found in class '%s'\n", pname, cls);
            continue;
        }
        d->data &= ~(1U << (perm_d->s.value - 1));
        fprintf(stderr, "  [-] Cleared perm '%s' from %s %s:%s\n", pname, src, tgt, cls);
    }

    /* If all bits cleared, remove the node entirely from the hash bucket.
       libsepol validates data!=0 for AVTAB_ALLOWED entries — a zero entry
       will cause policydb_to_image to fail with "Invalid access vector". */
    if(d->data == 0) {
        uint32_t hval = avtab_hash_key(&key, pdb->te_avtab.mask);
        avtab_ptr_t *bucket = &pdb->te_avtab.htable[hval];
        avtab_ptr_t prev = NULL, cur = *bucket;
        while(cur) {
            if(cur->key.source_type == key.source_type &&
               cur->key.target_type == key.target_type &&
               cur->key.target_class == key.target_class &&
               cur->key.specified  == key.specified) {
                /* Unlink */
                if(prev) prev->next = cur->next;
                else      *bucket   = cur->next;
                free(cur->datum.xperms);
                free(cur);
                pdb->te_avtab.nel--;
                fprintf(stderr, "  [-] Removed empty rule %s %s:%s from avtab\n", src, tgt, cls);
                break;
            }
            prev = cur;
            cur = cur->next;
        }
    }
    return 0;
}

/* Remove a genfscon entry matching fs_type + path prefix */
static int do_remove_genfscon(policydb_t *pdb, const char *fs_name, const char *path) {
    /* Walk ocontexts for OCON_ISID... genfscon is in genfs list */
    genfs_t *genfs = NULL, *prev_genfs = NULL;
    for(genfs = pdb->genfs; genfs; prev_genfs = genfs, genfs = genfs->next) {
        if(strcmp(genfs->fstype, fs_name) == 0) break;
    }
    if(!genfs) {
        fprintf(stderr, "  [~] remove_genfscon: fs '%s' not found, skipping\n", fs_name);
        return 0;
    }
    ocontext_t *ctx = NULL, *prev_ctx = NULL;
    for(ctx = genfs->head; ctx; prev_ctx = ctx, ctx = ctx->next) {
        if(ctx->u.name && strcmp(ctx->u.name, path) == 0) break;
    }
    if(!ctx) {
        fprintf(stderr, "  [~] remove_genfscon: path '%s' not found in fs '%s', skipping\n", path, fs_name);
        return 0;
    }
    /* Unlink from list */
    if(prev_ctx) prev_ctx->next = ctx->next;
    else genfs->head = ctx->next;
    free(ctx->u.name);
    context_destroy(&ctx->context[0]);
    free(ctx);
    fprintf(stderr, "  [-] Removed genfscon %s \"%s\"\n", fs_name, path);
    /* If genfs list is now empty, remove the genfs entry too */
    if(!genfs->head) {
        if(prev_genfs) prev_genfs->next = genfs->next;
        else pdb->genfs = genfs->next;
        free(genfs->fstype);
        free(genfs);
        fprintf(stderr, "  [-] Removed empty genfs entry for '%s'\n", fs_name);
    }
    return 0;
}

/* Remove permissive flag from a type */
static int do_remove_permissive(policydb_t *pdb, const char *type_name) {
    type_datum_t *td = get_or_create_type(pdb, type_name, 0, 0);
    if(!td) { fprintf(stderr, "  [~] remove_permissive: type '%s' not found\n", type_name); return 0; }
    ebitmap_set_bit(&pdb->permissive_map, td->s.value, 0);
    fprintf(stderr, "  [-] Cleared permissive on '%s'\n", type_name);
    return 0;
}

/* ---- Neverallow scan ----
 * Read-only walk of te_avtab looking for entries with AVTAB_NEVERALLOW set.
 * In standard Android kernel-format policies this is expected to be ZERO —
 * neverallow is a compile-time assertion that does not persist into the
 * runtime binary.  However, some vendor binaries (notably some Mediatek
 * vendor sepolicy variants) have been observed to ship non-standard
 * artifacts.  This scan exists purely to surface those cases.
 *
 * Findings are emitted on stderr in a machine-parseable form:
 *   NEVERALLOW_FINDING src=<name> tgt=<name> cls=<name> perms=<bits>
 * One line per matching avtab entry.  A summary line follows:
 *   NEVERALLOW_SCAN_TOTAL=<n>
 */
struct scan_ctx {
    policydb_t *pdb;
    int count;
};

static int scan_walker(avtab_key_t *k, avtab_datum_t *d, void *args) {
    struct scan_ctx *ctx = (struct scan_ctx *)args;
    if(!(k->specified & AVTAB_NEVERALLOW)) return 0;

    /* Resolve names from indices.  Indices are 1-based; 0 means 'self' for
     * source (or unresolvable).  Bounds-check before dereferencing. */
    const char *src_name = "?";
    const char *tgt_name = "?";
    const char *cls_name = "?";

    if(k->source_type > 0 && k->source_type <= ctx->pdb->p_types.nprim &&
       ctx->pdb->p_type_val_to_name &&
       ctx->pdb->p_type_val_to_name[k->source_type - 1])
        src_name = ctx->pdb->p_type_val_to_name[k->source_type - 1];

    if(k->target_type > 0 && k->target_type <= ctx->pdb->p_types.nprim &&
       ctx->pdb->p_type_val_to_name &&
       ctx->pdb->p_type_val_to_name[k->target_type - 1])
        tgt_name = ctx->pdb->p_type_val_to_name[k->target_type - 1];

    if(k->target_class > 0 && k->target_class <= ctx->pdb->p_classes.nprim &&
       ctx->pdb->p_class_val_to_name &&
       ctx->pdb->p_class_val_to_name[k->target_class - 1])
        cls_name = ctx->pdb->p_class_val_to_name[k->target_class - 1];

    fprintf(stderr, "NEVERALLOW_FINDING src=%s tgt=%s cls=%s perms=0x%08x\n",
            src_name, tgt_name, cls_name, d->data);
    ctx->count++;
    return 0;
}

static int do_scan_neverallows(policydb_t *pdb) {
    struct scan_ctx ctx = { .pdb = pdb, .count = 0 };
    avtab_map(&pdb->te_avtab, scan_walker, &ctx);
    /* Also scan conditional avtab — some policies stash neverallows there */
    avtab_map(&pdb->te_cond_avtab, scan_walker, &ctx);
    fprintf(stderr, "NEVERALLOW_SCAN_TOTAL=%d\n", ctx.count);
    return 0;
}

/* ---- JSON rule application ---- */

/* Very small JSON string-array parser — only handles what we emit */
static char **parse_str_array(const char **p, int *count) {
    skip_ws(p);
    if(**p != '[') return NULL;
    (*p)++;
    char **arr = NULL;
    *count = 0;
    while(1) {
        skip_ws(p);
        if(**p == ']') { (*p)++; break; }
        if(**p == ',') { (*p)++; continue; }
        char *s = parse_string(p);
        if(!s) break;
        arr = realloc(arr, sizeof(char*)*(*count+1));
        arr[(*count)++] = s;
    }
    return arr;
}

static int apply_rules(policydb_t *pdb, const char *json_path) {
    FILE *f = fopen(json_path, "r");
    if(!f) { fprintf(stderr, "Cannot open rules file: %s\n", json_path); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    char *buf = malloc(sz+1);
    fread(buf, 1, sz, f); buf[sz] = 0; fclose(f);

    const char *p = buf;
    skip_ws(&p);
    if(*p != '[') { fprintf(stderr, "Expected JSON array\n"); free(buf); return -1; }
    p++;

    int total = 0, ok = 0;
    while(1) {
        skip_ws(&p);
        if(*p == ']' || *p == '\0') break;
        if(*p == ',') { p++; continue; }
        if(*p != '{') { p++; continue; }
        p++;

        /* Parse object key-value pairs */
        char *op=NULL, *src=NULL, *tgt=NULL, *cls=NULL, *type_name=NULL;
        char *attr=NULL, *def_type=NULL, *tr_name=NULL;
        char **perms=NULL; int nperms=0;

        while(1) {
            skip_ws(&p);
            if(*p == '}' || *p == '\0') break;
            if(*p == ',') { p++; continue; }
            char *key = parse_string(&p);
            if(!key) break;
            skip_ws(&p);
            if(*p == ':') p++;
            skip_ws(&p);

            if(strcmp(key,"op")==0)       { op        = parse_string(&p); }
            else if(strcmp(key,"src")==0) { src       = parse_string(&p); }
            else if(strcmp(key,"tgt")==0) { tgt       = parse_string(&p); }
            else if(strcmp(key,"cls")==0) { cls       = parse_string(&p); }
            else if(strcmp(key,"type")==0){ type_name = parse_string(&p); }
            else if(strcmp(key,"name")==0){ type_name = parse_string(&p); } /* reuse for type decl */
            else if(strcmp(key,"attr")==0){ attr      = parse_string(&p); }
            else if(strcmp(key,"default")==0){ def_type = parse_string(&p); }
            else if(strcmp(key,"tr_name")==0){ tr_name = parse_string(&p); }
            else if(strcmp(key,"perms")==0){ perms = parse_str_array(&p, &nperms); }
            else {
                /* skip unknown value */
                if(*p == '"') parse_string(&p);
                else while(*p && *p != ',' && *p != '}') p++;
            }
            free(key);
        }
        if(*p == '}') p++;

        total++;
        int r = 0;
        if(!op) { fprintf(stderr, "  [!] Rule missing 'op'\n"); goto next; }

        fprintf(stderr, "  Applying: %s", op);
        if(src) fprintf(stderr, " %s", src);
        if(tgt) fprintf(stderr, " -> %s", tgt);
        if(cls) fprintf(stderr, " (%s)", cls);
        if(type_name) fprintf(stderr, " type=%s", type_name);
        if(attr) fprintf(stderr, " attr=%s", attr);
        fprintf(stderr, "\n");

        if(strcmp(op,"allow")==0 && src && tgt && cls && perms)
            r = do_av_rule(pdb, src, tgt, cls, perms, nperms, AVTAB_ALLOWED);
        else if(strcmp(op,"auditallow")==0 && src && tgt && cls && perms)
            r = do_av_rule(pdb, src, tgt, cls, perms, nperms, AVTAB_AUDITALLOW);
        else if(strcmp(op,"dontaudit")==0 && src && tgt && cls && perms)
            r = do_av_rule(pdb, src, tgt, cls, perms, nperms, AVTAB_AUDITDENY);
        else if(strcmp(op,"permissive")==0 && type_name)
            r = do_permissive(pdb, type_name);
        else if(strcmp(op,"type")==0 && type_name) {
            type_datum_t *td = get_or_create_type(pdb, type_name, 0, 1);
            if(!td) r = -1;
            if(td && attr) {
                /* also set the attribute */
                type_datum_t *ad = get_or_create_type(pdb, attr, 1, 0);
                if(ad) do_typeattribute(pdb, type_name, attr);
            }
        }
        else if(strcmp(op,"attribute")==0 && type_name) {
            type_datum_t *td = get_or_create_type(pdb, type_name, 1, 1);
            if(!td) r = -1;
        }
        else if(strcmp(op,"typeattribute")==0 && type_name && attr)
            r = do_typeattribute(pdb, type_name, attr);
        else if(strcmp(op,"type_transition")==0 && src && tgt && cls && def_type)
            r = do_type_transition(pdb, src, tgt, cls, def_type, tr_name);
        else if(strcmp(op,"remove_allow")==0 && src && tgt && cls && perms)
            r = do_remove_av_rule(pdb, src, tgt, cls, perms, nperms);
        else if(strcmp(op,"remove_genfscon")==0 && src && tgt)
            /* reuse src=fs_type, tgt=path */
            r = do_remove_genfscon(pdb, src, tgt);
        else if(strcmp(op,"remove_permissive")==0 && type_name)
            r = do_remove_permissive(pdb, type_name);
        else if(strcmp(op,"scan_neverallows")==0)
            r = do_scan_neverallows(pdb);
        else
            fprintf(stderr, "  [!] Unknown or incomplete rule: %s\n", op);

        if(r == 0) ok++;

next:
        free(op); free(src); free(tgt); free(cls); free(type_name);
        free(attr); free(def_type); free(tr_name);
        for(int i=0;i<nperms;i++) free(perms[i]);
        free(perms);
    }

    free(buf);
    fprintf(stderr, "  Rules applied: %d/%d succeeded\n", ok, total);
    return (ok == total) ? 0 : -1;
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        fprintf(stderr, "Usage: %s <rules.json> <policy_file> [--scan-only]\n", argv[0]);
        return 1;
    }
    int scan_only = (argc >= 4 && strcmp(argv[3], "--scan-only") == 0);

    init_handle();

    policydb_t pdb;
    fprintf(stderr, "[*] Loading policy: %s\n", argv[2]);
    if(load_policy(argv[2], &pdb) < 0) return 1;
    fprintf(stderr, "[*] Policy version: %u\n", pdb.policyvers);

    fprintf(stderr, "[*] Applying rules from: %s\n", argv[1]);
    if(apply_rules(&pdb, argv[1]) < 0) {
        /* Non-fatal — still write partial results (unless scan-only) */
        fprintf(stderr, "[!] Some rules failed (continuing)\n");
    }

    if(!scan_only) {
        fprintf(stderr, "[*] Writing patched policy: %s\n", argv[2]);
        if(save_policy(argv[2], &pdb) < 0) {
            policydb_destroy(&pdb);
            return 1;
        }
    } else {
        fprintf(stderr, "[*] Scan-only mode — policy unchanged\n");
    }

    policydb_destroy(&pdb);
    fprintf(stderr, "[*] Done.\n");
    return 0;
}
"""

# ---------------------------------------------------------------------------
# .te file parser
# ---------------------------------------------------------------------------

@dataclass
class TeRule:
    op: str
    src: str = ""
    tgt: str = ""
    cls: str = ""
    perms: list = field(default_factory=list)
    type_name: str = ""
    attr: str = ""
    default: str = ""
    tr_name: str = ""
    # genfscon fields
    fs_type: str = ""   # e.g. "proc"
    path: str = ""      # e.g. "/q20_switch_key_mouse"
    context: str = ""   # e.g. "u:object_r:q25_trackpad_proc:s0"


@dataclass
class RemoveRule:
    """
    Represents a removal directive from a --remove-te file.

    Supported directives (same syntax as .te but prefixed with 'remove_'):
      remove_allow src tgt:cls { perms };
      remove_genfscon fs "/path";
      remove_permissive type;
      remove_type type;          -- CIL only (cannot safely remove types from binary)
      remove_typeattribute type attr;  -- CIL only
    """
    op: str          # remove_allow | remove_genfscon | remove_permissive |
                     # remove_type | remove_typeattribute
    src: str = ""    # also fs_type for genfscon
    tgt: str = ""    # also path for genfscon
    cls: str = ""
    perms: list = field(default_factory=list)
    type_name: str = ""
    attr: str = ""


def _strip_comments(text: str) -> str:
    """Remove # comments and C-style block comments."""
    # Remove block comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Remove line comments
    text = re.sub(r'#[^\n]*', '', text)
    return text


# ----- AOSP te_macros expansion ----------------------------------------------
#
# AOSP's sepolicy build pipeline runs `m4` over .te files before compiling to
# CIL, expanding standard macros defined in system/sepolicy/public/te_macros.
# Because this tool processes .te files directly (no m4 step), it has to
# expand the most common macros itself.  Coverage is intentionally limited
# to the patterns that come up in real-world add-a-domain workflows.
#
# The expansion is textual: each macro call is replaced with the rules it
# generates, then parse_te_file() sees ordinary `allow` / `type_transition`
# statements and processes them normally.  Naming conventions match AOSP
# te_macros so user-written .te files port cleanly.
#
# Macros currently expanded:
#   init_daemon_domain(D)            — full init→D transition + domain attribution
#   domain_auto_trans(SRC, EXEC, D)  — automatic process transition (no init)
#   domain_trans(SRC, EXEC, D)       — manual transition (allow but no auto)
#   set_prop(D, P)                   — D writes property type P
#   get_prop(D, P)                   — D reads property type P
#   binder_use(D)                    — D talks to the binder driver
#   binder_call(SRC, DST)            — SRC makes binder calls into DST
#   binder_service(D)                — D registers as a binder service
#   unix_socket_connect(D, S, SERVER) — D connects to SERVER's S socket
#
# Any other macros must be expanded manually before passing the .te through
# this tool; unknown macros are left in place and the parser will emit a
# "cannot parse rule" warning on them, which is the right signal.

def _expand_te_macros(text: str) -> str:
    """Expand common AOSP te_macros into their underlying rule statements.

    Operates on the post-comment-stripped text.  Each macro call is replaced
    inline by the rule sequence it generates, joined with newlines so the
    caller's `;`-split statement loop sees them as separate statements.
    """

    # Match macro_name(arg1, arg2, ...) — args may contain whitespace.
    # Each macro call is a single-line invocation in normal .te files;
    # we don't try to handle line-continuation backslashes.
    macro_call_re = re.compile(
        r'\b(init_daemon_domain|domain_auto_trans|domain_trans|set_prop|get_prop|'
        r'binder_use|binder_call|binder_service|unix_socket_connect)\s*'
        r'\(([^)]*)\)\s*;?',
        re.MULTILINE,
    )

    def expand_one(match: 're.Match') -> str:
        name = match.group(1)
        args = [a.strip() for a in match.group(2).split(',') if a.strip()]
        try:
            rules = _MACRO_DEFINITIONS[name](*args)
        except (TypeError, KeyError) as e:
            print(f"  [!] macro {name}({', '.join(args)}): {e}; left in place")
            return match.group(0)
        return '\n' + '\n'.join(rules) + '\n'

    return macro_call_re.sub(expand_one, text)


# Each macro definition is a function that takes the macro's textual args
# and returns a list of rule strings (each ending in ';').  Keeping each
# macro as a small function makes the expansion easy to audit against
# system/sepolicy/public/te_macros in AOSP.

def _macro_init_daemon_domain(d: str) -> list[str]:
    """init_daemon_domain(D): full init→D process transition + domain attribution.

    Mirrors AOSP's te_macros, minus the M4-time `define()` boilerplate.
    Includes the `coredomain` attribution that the auto-coredomain detector
    would otherwise infer separately — by emitting it here we make the .te
    self-documenting, and the synthesizer's idempotency check will skip
    re-adding it.
    """
    return [
        # Type declaration with both domain attributes
        f"type {d}, domain, coredomain;",
        # Process transition perms (the four init needs to launch a daemon)
        f"allow init {d}:process transition;",
        f"allow init {d}:process {{ siginh rlimitinh noatsecure }};",
        # The new domain must be reachable via exec'ing its labeled binary
        f"allow {d} {d}_exec:file {{ entrypoint open read execute getattr map }};",
        # init's stdin/stdout/stderr fds carry across exec
        f"allow {d} init:fd use;",
        # The auto-transition: init exec's a {d}_exec-labeled binary → {d} domain
        f"type_transition init {d}_exec:process {d};",
    ]


def _macro_domain_auto_trans(src: str, exec_t: str, dst: str) -> list[str]:
    """domain_auto_trans(SRC, EXEC, DST): SRC auto-transitions to DST when
    exec'ing a binary labeled EXEC."""
    return [
        f"allow {src} {exec_t}:file {{ getattr open read execute map }};",
        f"allow {src} {dst}:process transition;",
        f"allow {dst} {exec_t}:file {{ entrypoint open read execute getattr map }};",
        f"allow {dst} {src}:fd use;",
        f"type_transition {src} {exec_t}:process {dst};",
        f"allow {src} {dst}:process {{ siginh rlimitinh noatsecure }};",
    ]


def _macro_domain_trans(src: str, exec_t: str, dst: str) -> list[str]:
    """domain_trans(SRC, EXEC, DST): like domain_auto_trans but without the
    type_transition rule (caller must invoke setexeccon)."""
    return [
        f"allow {src} {exec_t}:file {{ getattr open read execute map }};",
        f"allow {src} {dst}:process transition;",
        f"allow {dst} {exec_t}:file {{ entrypoint open read execute getattr map }};",
        f"allow {dst} {src}:fd use;",
        f"allow {src} {dst}:process {{ siginh rlimitinh noatsecure }};",
    ]


def _macro_set_prop(d: str, p: str) -> list[str]:
    """set_prop(D, P): allow D to set properties of type P."""
    return [
        f"allow {d} {p}:property_service set;",
        # Property-socket plumbing — same expansion as unix_socket_connect(D, property, init)
        f"allow {d} property_socket:sock_file write;",
        f"allow {d} init:unix_stream_socket connectto;",
    ]


def _macro_get_prop(d: str, p: str) -> list[str]:
    """get_prop(D, P): allow D to read properties of type P (file-based reads)."""
    return [
        f"allow {d} {p}:file {{ getattr open read map }};",
    ]


def _macro_binder_use(d: str) -> list[str]:
    """binder_use(D): allow D to use the binder driver.

    AOSP's te_macros expansion of binder_use(D) is essentially:
      - servicemanager interaction (find/add/check perms come via separate
        per-service macros; binder_use only sets up the underlying transport)
      - process inspection of D by servicemanager
    The /dev/binder chr_file permission is provided by ueventd's labeling
    and the `binder` class itself, not by a file-based allow rule.
    """
    return [
        f"allow {d} servicemanager:binder {{ call transfer }};",
        f"allow servicemanager {d}:binder transfer;",
        f"allow servicemanager {d}:dir search;",
        f"allow servicemanager {d}:file {{ read open }};",
        f"allow servicemanager {d}:process getattr;",
    ]


def _macro_binder_call(src: str, dst: str) -> list[str]:
    """binder_call(SRC, DST): allow SRC to make binder calls into DST."""
    return [
        f"allow {src} {dst}:binder {{ call transfer }};",
        f"allow {dst} {src}:binder transfer;",
        f"allow {src} {dst}:fd use;",
    ]


def _macro_binder_service(d: str) -> list[str]:
    """binder_service(D): D registers binder services."""
    return [
        f"typeattribute {d} binderservicedomain;",
    ]


def _macro_unix_socket_connect(d: str, sock: str, server: str) -> list[str]:
    """unix_socket_connect(D, SOCK, SERVER): D connects to SERVER's SOCK socket."""
    return [
        f"allow {d} {sock}_socket:sock_file write;",
        f"allow {d} {server}:unix_stream_socket connectto;",
    ]


_MACRO_DEFINITIONS = {
    'init_daemon_domain':   _macro_init_daemon_domain,
    'domain_auto_trans':    _macro_domain_auto_trans,
    'domain_trans':         _macro_domain_trans,
    'set_prop':             _macro_set_prop,
    'get_prop':             _macro_get_prop,
    'binder_use':           _macro_binder_use,
    'binder_call':          _macro_binder_call,
    'binder_service':       _macro_binder_service,
    'unix_socket_connect':  _macro_unix_socket_connect,
}


# ----- AOSP global_macros expansion -----------------------------------------
#
# Separate from the function-style te_macros above, AOSP also defines a set
# of permission and class GROUPING macros in
#   system/sepolicy/public/global_macros
# These appear as bare identifiers in the perm slot or class slot of a rule,
# not as function calls.  Examples:
#
#   allow gapps_clean toolbox_exec:file rx_file_perms;
#   allow domain self:capability_class_set { setuid setgid };
#
# Like te_macros, they are m4-expanded before the policy reaches checkpolicy
# /secilc.  Because this tool processes .te files without running m4, we have
# to flatten them ourselves; otherwise the C helper sees `rx_file_perms` as
# a literal permission name, fails to find it in the file class's perm table,
# and either drops the rule or produces broken CIL that secilc later rejects.
#
# Values below mirror system/sepolicy/public/global_macros from upstream
# AOSP main verbatim (single-source-of-truth — easy to diff against
# https://android.googlesource.com/platform/system/sepolicy/+/main/public/global_macros
# if the macro set evolves).  Definitions may reference other macros
# (e.g. rx_file_perms -> r_file_perms x_file_perms); _resolve_macros()
# flattens recursively to a final list of concrete permissions/classes.

# Permission groupings.  When one of these names appears in the perm slot
# of an allow / auditallow / dontaudit / remove_allow rule, it is replaced
# (and recursively flattened) into its concrete permission set.
_GLOBAL_PERM_MACROS: dict[str, str] = {
    # ---- file perms ----
    'x_file_perms':         'getattr execute execute_no_trans map',
    'r_file_perms':         'getattr open read ioctl lock map watch watch_reads',
    'w_file_perms':         'open append write lock map',
    'rx_file_perms':        'r_file_perms x_file_perms',
    'ra_file_perms':        'r_file_perms append',
    'rw_file_perms':        'r_file_perms w_file_perms',
    'rwx_file_perms':       'rw_file_perms x_file_perms',
    'create_file_perms':    'create rename setattr unlink rw_file_perms',

    # ---- dir perms ----
    'r_dir_perms':          'open getattr read search ioctl lock watch watch_reads',
    'w_dir_perms':          'open search write add_name remove_name lock',
    'ra_dir_perms':         'r_dir_perms add_name write',
    'rw_dir_perms':         'r_dir_perms w_dir_perms',
    'create_dir_perms':     'create reparent rename rmdir setattr rw_dir_perms',

    # ---- ipc perms ----
    'r_ipc_perms':          'getattr read associate unix_read',
    'w_ipc_perms':          'write unix_write',
    'rw_ipc_perms':         'r_ipc_perms w_ipc_perms',
    'create_ipc_perms':     'create setattr destroy rw_ipc_perms',

    # ---- socket perms ----
    'rw_socket_perms':
        'ioctl read getattr write setattr lock append bind connect '
        'getopt setopt shutdown map',
    'rw_socket_perms_no_ioctl':
        'read getattr write setattr lock append bind connect '
        'getopt setopt shutdown map',
    'create_socket_perms':            'create rw_socket_perms',
    'create_socket_perms_no_ioctl':   'create rw_socket_perms_no_ioctl',
    'rw_stream_socket_perms':         'rw_socket_perms listen accept',
    'create_stream_socket_perms':     'create rw_stream_socket_perms',
}

# Class groupings.  When one of these names appears in the class slot of
# a rule, it expands to a set of classes; the rule cross-products into one
# rule per concrete class (the existing brace-set machinery already does the
# cross-product, so we just feed it a longer class list).
_GLOBAL_CLASS_MACROS: dict[str, str] = {
    'capability_class_set':         'capability capability2 cap_userns cap2_userns',
    'global_capability_class_set':  'capability cap_userns',
    'global_capability2_class_set': 'capability2 cap2_userns',
    'devfile_class_set':            'chr_file blk_file',
    'notdevfile_class_set':         'file lnk_file sock_file fifo_file',
    'file_class_set':               'devfile_class_set notdevfile_class_set',
    'dir_file_class_set':           'dir file_class_set',
    'dgram_socket_class_set':       'udp_socket unix_dgram_socket',
    'stream_socket_class_set':      'tcp_socket unix_stream_socket sctp_socket',
    'unpriv_socket_class_set':
        'tcp_socket udp_socket unix_stream_socket unix_dgram_socket sctp_socket',
    'network_socket_class_set':     'icmp_socket rawip_socket tcp_socket udp_socket',
    'ipc_class_set':                'sem msgq shm ipc',
    # socket_class_set in upstream has ~60 members covering every kernel
    # socket family.  It is essentially never useful in patch workflows
    # (you almost always want a specific family) and would inflate rule
    # counts by 60x if accidentally used, so it is deliberately omitted.
    # Add it here if a real need arises.
}


def _resolve_macros(items: list[str], macros: dict[str, str]) -> list[str]:
    """Flatten a token list against a global_macros dictionary.

    For each token in `items`, if it matches a key in `macros`, the value's
    space-separated tokens are substituted in place and themselves checked
    for further macros (recursive — handles rx_file_perms -> r_file_perms
    x_file_perms -> their final perms).  Tokens that are not macros pass
    through unchanged.

    Output order matches first-occurrence order in the resolved stream, with
    duplicates removed (allow rules with duplicate perms are wasteful but
    harmless; we dedup for cleanliness).  A 16-deep guard prevents infinite
    recursion if a future edit to the macro dicts introduces a cycle.
    """
    out: list[str] = []
    seen: set[str] = set()

    def walk(token: str, depth: int) -> None:
        if depth > 16:
            # Defensive guard: cycle or absurd nesting.  Leave the offending
            # token in place rather than dropping it — the downstream parser
            # will then surface it as an unknown perm/class, which is the
            # right diagnostic.
            if token not in seen:
                seen.add(token); out.append(token)
            return
        expansion = macros.get(token)
        if expansion is None:
            if token not in seen:
                seen.add(token); out.append(token)
            return
        for inner in expansion.split():
            walk(inner, depth + 1)

    for it in items:
        walk(it, 0)
    return out


def _expand_braces(tokens: list[str]) -> list[list[str]]:
    """
    Given a token list like ['allow', 'foo', 'bar:baz', '{', 'read', 'write', '}', ';'],
    expand into one rule per cross-product of bracketed sets.
    Returns a list of flat token lists (one per expanded rule).
    """
    # Find brace groups and replace with their items
    # We'll do a simple iterative expansion
    def expand_one(toks: list[str]) -> list[list[str]]:
        """Expand first brace group found."""
        try:
            start = toks.index('{')
            end = toks.index('}', start)
        except ValueError:
            return [toks]  # no braces
        pre = toks[:start]
        group = toks[start+1:end]
        post = toks[end+1:]
        result = []
        for item in group:
            result.append(pre + [item] + post)
        return result

    current = [tokens]
    while True:
        next_round = []
        changed = False
        for toks in current:
            expanded = expand_one(toks)
            next_round.extend(expanded)
            if expanded != [toks]:
                changed = True
        current = next_round
        if not changed:
            break
    return current


def parse_te_file(path: str) -> list[TeRule]:
    """Parse a .te policy file into a list of TeRule objects."""
    text = Path(path).read_text(errors='replace')
    text = _strip_comments(text)
    # Expand AOSP te_macros (init_daemon_domain, set_prop, binder_call, etc.)
    # before statement splitting so the rest of the parser sees only plain
    # allow/typetransition/etc. statements.
    text = _expand_te_macros(text)

    rules = []
    # Split into statements on ';'
    statements = text.split(';')
    for stmt in statements:
        stmt = stmt.strip()
        if not stmt:
            continue

        # Tokenize — split on whitespace and keep : as part of tgt:cls token
        tokens = stmt.split()
        if not tokens:
            continue

        op = tokens[0]

        # ---- allow / auditallow / dontaudit / neverallow ----
        if op in ('allow', 'auditallow', 'dontaudit', 'neverallow'):
            if op == 'neverallow':
                print(f"  [~] Skipping neverallow (not enforceable at binary patch time)")
                continue
            # Pattern: op src tgt_cls { perms } or op src tgt_cls perm
            # tgt_cls is like "foo:bar" or "foo:{ class1 class2 }"
            # perms can be bare word or { p1 p2 ... }
            rest = ' '.join(tokens[1:])
            # Extract src, tgt:cls, perms
            # src and tgt may be bare words or brace-sets like { type1 type2 }
            m = re.match(
                r'(\{[^}]*\}|\S+)\s+'             # src (bare word or {set})
                r'(\{[^}]*\}|\S+)\s*:\s*'         # tgt (bare word or {set}):
                r'(\{[^}]*\}|\S+)\s*'             # cls (bare word or {set})
                r'(\{[^}]*\}|\S+)',               # perms (bare word or {set})
                rest
            )
            if not m:
                print(f"  [!] Cannot parse rule: {op} {rest!r}")
                continue

            raw_src, raw_tgt, raw_cls, raw_perms = m.group(1), m.group(2), m.group(3), m.group(4)

            def extract_set(s: str) -> list[str]:
                s = s.strip()
                if s.startswith('{'):
                    # Split on whitespace AND commas — some .te files use
                    # C-style commas inside brace groups (`{ read, open, getattr }`).
                    # Without comma-splitting the tokens come out as
                    # ['read,', 'open,', 'getattr'] and survive all the way
                    # through rules_to_cil to produce invalid CIL like
                    # `(file (read, open, getattr))` which secilc rejects.
                    return [x for x in re.split(r'[\s,]+', s.strip('{}')) if x]
                return [s] if s != '~all' else []  # skip complement for now

            srcs = extract_set(raw_src)
            tgts = extract_set(raw_tgt)
            clss = extract_set(raw_cls)
            perms = extract_set(raw_perms)

            # Expand AOSP global_macros (rx_file_perms, create_dir_perms,
            # file_class_set, capability_class_set, etc.) into their concrete
            # permission / class sets.  See _GLOBAL_PERM_MACROS comment for
            # rationale.  Done after extract_set so we resolve both bare
            # macro usage (`... rx_file_perms;`) and macros inside brace
            # groups (`{ rx_file_perms append }`) with the same path.
            perms = _resolve_macros(perms, _GLOBAL_PERM_MACROS)
            clss  = _resolve_macros(clss,  _GLOBAL_CLASS_MACROS)

            for s in srcs:
                for t in tgts:
                    for c in clss:
                        rules.append(TeRule(
                            op=op, src=s, tgt=t, cls=c, perms=perms
                        ))

        # ---- permissive ----
        elif op == 'permissive':
            if len(tokens) >= 2:
                rules.append(TeRule(op='permissive', type_name=tokens[1]))

        # ---- type declaration ----
        elif op == 'type':
            # type foo; OR type foo, attr1, attr2;
            if len(tokens) >= 2:
                name = tokens[1].rstrip(',')
                attrs = [t.strip(', ') for t in tokens[2:] if t.strip(', ')]
                if not attrs:
                    rules.append(TeRule(op='type', type_name=name))
                else:
                    rules.append(TeRule(op='type', type_name=name, attr=attrs[0]))
                    for a in attrs[1:]:
                        rules.append(TeRule(op='typeattribute', type_name=name, attr=a))

        # ---- attribute declaration ----
        elif op == 'attribute':
            if len(tokens) >= 2:
                rules.append(TeRule(op='attribute', type_name=tokens[1]))

        # ---- typeattribute ----
        elif op == 'typeattribute':
            # typeattribute foo attr1, attr2;
            if len(tokens) >= 3:
                name = tokens[1]
                for attr in tokens[2:]:
                    attr = attr.strip(', ')
                    if attr:
                        rules.append(TeRule(op='typeattribute', type_name=name, attr=attr))

        # ---- mlstrustedsubject / mlstrustedobject ----
        # Bare-directive shorthand:
        #   mlstrustedsubject foo;
        #   mlstrustedsubject foo, bar, baz;
        # is sugar for `typeattribute foo mlstrustedsubject;` (one per type).
        # Same for mlstrustedobject. These are MLS-bypass attributes; emitting
        # them as ordinary typeattribute rules reuses the existing CIL path
        # (lines below in rules_to_cil) which produces:
        #   (typeattributeset mlstrustedsubject (foo))
        # which is the correct CIL form. Without this case the parser would
        # hit the unrecognized-keyword branch and silently drop the directive,
        # leaving the domain without MLS-trusted status and causing bootloops
        # on MLS-enforcing builds.
        elif op in ('mlstrustedsubject', 'mlstrustedobject'):
            if len(tokens) >= 2:
                for name in tokens[1:]:
                    name = name.strip(', ')
                    if name:
                        rules.append(TeRule(op='typeattribute',
                                            type_name=name, attr=op))
            else:
                print(f"  [!] {op}: expected at least one type name")

        # ---- type_transition ----
        elif op == 'type_transition':
            # type_transition src tgt:cls default; OR with name at end
            rest = ' '.join(tokens[1:])
            m = re.match(
                r'(\S+)\s+(\S+)\s*:\s*(\S+)\s+(\S+)(?:\s+"([^"]+)")?',
                rest
            )
            if m:
                rules.append(TeRule(
                    op='type_transition',
                    src=m.group(1), tgt=m.group(2), cls=m.group(3),
                    default=m.group(4), tr_name=m.group(5) or ''
                ))
            else:
                print(f"  [!] Cannot parse type_transition: {rest!r}")

        # ---- genfscon ----
        elif op == 'genfscon':
            # genfscon proc "/path/to/file" u:object_r:mytype:s0
            # genfscon proc "/path/to/file" -f file u:object_r:mytype:s0  (ignore -f variant)
            rest_tokens = tokens[1:]
            if len(rest_tokens) >= 3:
                fs = rest_tokens[0]
                path = rest_tokens[1].strip('"').strip("'")
                # skip optional "-f <filetype>" modifier
                ctx_tok = rest_tokens[2]
                if ctx_tok == '-f' and len(rest_tokens) >= 5:
                    ctx_tok = rest_tokens[4]
                elif ctx_tok == '-f' and len(rest_tokens) >= 4:
                    ctx_tok = rest_tokens[3]
                rules.append(TeRule(op='genfscon', fs_type=fs, path=path, context=ctx_tok))
            else:
                print(f"  [!] Cannot parse genfscon: {' '.join(tokens)!r}")

        # ---- skip known non-rule keywords ----
        elif op in ('require', 'optional', 'ifdef', 'ifndef', 'endif',
                    'class', 'common', 'inherits', 'typealias', 'typebounds',
                    'role', 'user', 'sid', 'sensitivity', 'category',
                    'level', 'mlsconstrain', 'mlsvalidatetrans',
                    'constrain', 'validatetrans', 'define', 'gen_require',
                    'bool', 'if', 'else'):
            pass  # silently skip unsupported constructs

        else:
            if op and not op.startswith('#'):
                print(f"  [~] Unrecognized keyword, skipping: {op!r}")

    return rules


def parse_remove_te_file(path: str) -> list[RemoveRule]:
    """
    Parse a removal .te file.  Syntax is identical to a regular .te file
    except that each statement is prefixed with 'remove_':

      remove_allow platform_app q25_led_sysfs:file { open read write getattr };
      remove_genfscon sysfs "/class/leds/red/brightness";
      remove_permissive mytype;
      remove_type q25_led_sysfs;
      remove_typeattribute q25_led_sysfs sysfs_type;

    Comments (#) are stripped.  Lines not starting with 'remove_' are ignored.
    """
    text = Path(path).read_text(errors='replace')
    text = _strip_comments(text)

    rules: list[RemoveRule] = []
    for stmt in text.split(';'):
        stmt = stmt.strip()
        if not stmt:
            continue
        tokens = stmt.split()
        if not tokens:
            continue
        op = tokens[0]
        if not op.startswith('remove_'):
            continue

        # remove_allow src tgt:cls { perms }
        if op == 'remove_allow':
            rest = ' '.join(tokens[1:])
            m = re.match(
                r'(\S+)\s+(\S+)\s*:\s*(\{[^}]*\}|\S+)\s*(\{[^}]*\}|\S+)',
                rest
            )
            if not m:
                print(f"  [!] Cannot parse: {op} {rest!r}")
                continue
            raw_tgt, raw_cls, raw_perms = m.group(2), m.group(3), m.group(4)

            def extract_set(s: str) -> list[str]:
                s = s.strip()
                if s.startswith('{'):
                    return [x.strip() for x in s.strip('{}').split() if x.strip()]
                return [s]

            for s in extract_set(m.group(1)):
                for t in extract_set(raw_tgt):
                    # Expand class macros so remove rules also match the
                    # cross-product the corresponding allow rule produced
                    # (e.g. a remove against capability_class_set must
                    # remove from all four concrete classes).
                    for c in _resolve_macros(extract_set(raw_cls),
                                             _GLOBAL_CLASS_MACROS):
                        rules.append(RemoveRule(
                            op='remove_allow', src=s, tgt=t, cls=c,
                            perms=_resolve_macros(extract_set(raw_perms),
                                                  _GLOBAL_PERM_MACROS)
                        ))

        # remove_genfscon fs "/path"
        elif op == 'remove_genfscon':
            if len(tokens) >= 3:
                fs = tokens[1]
                path_val = tokens[2].strip('"').strip("'")
                rules.append(RemoveRule(op='remove_genfscon', src=fs, tgt=path_val))
            else:
                print(f"  [!] Cannot parse: {op} {' '.join(tokens[1:])!r}")

        # remove_permissive type
        elif op == 'remove_permissive':
            if len(tokens) >= 2:
                rules.append(RemoveRule(op='remove_permissive', type_name=tokens[1]))

        # remove_type type  (CIL only — cannot remove types from binary safely)
        elif op == 'remove_type':
            if len(tokens) >= 2:
                rules.append(RemoveRule(op='remove_type', type_name=tokens[1]))
                print(f"  [~] remove_type '{tokens[1]}': CIL only (binary type removal not supported)")

        # remove_typeattribute type attr
        elif op == 'remove_typeattribute':
            if len(tokens) >= 3:
                rules.append(RemoveRule(op='remove_typeattribute',
                                        type_name=tokens[1], attr=tokens[2].strip(',')))

        # remove_mlstrustedsubject / remove_mlstrustedobject
        # Shorthand for `remove_typeattribute foo mlstrustedsubject;`.
        # Accepts one or more type names:
        #   remove_mlstrustedsubject foo;
        #   remove_mlstrustedsubject foo, bar;
        elif op in ('remove_mlstrustedsubject', 'remove_mlstrustedobject'):
            attr = op[len('remove_'):]  # strip 'remove_' prefix → mlstrustedsubject
            if len(tokens) >= 2:
                for name in tokens[1:]:
                    name = name.strip(', ')
                    if name:
                        rules.append(RemoveRule(op='remove_typeattribute',
                                                type_name=name, attr=attr))
            else:
                print(f"  [!] {op}: expected at least one type name")

        else:
            print(f"  [~] Unrecognized remove directive, skipping: {op!r}")

    return rules


def rules_to_json(rules: list[TeRule]) -> str:
    """Serialize rules to JSON for the C helper."""
    out = []
    for r in rules:
        obj: dict = {"op": r.op}
        if r.op in ('allow', 'auditallow', 'dontaudit'):
            obj.update(src=r.src, tgt=r.tgt, cls=r.cls, perms=r.perms)
        elif r.op == 'permissive':
            obj["type"] = r.type_name
        elif r.op == 'type':
            obj["name"] = r.type_name
            if r.attr:
                obj["attr"] = r.attr
        elif r.op == 'attribute':
            obj["name"] = r.type_name
        elif r.op == 'typeattribute':
            obj.update(type=r.type_name, attr=r.attr)
        elif r.op == 'type_transition':
            obj.update(src=r.src, tgt=r.tgt, cls=r.cls,
                       default=r.default, tr_name=r.tr_name)
        elif r.op == 'genfscon':
            continue  # genfscon is CIL-only, not sent to binary patcher
        out.append(obj)
    return json.dumps(out, indent=2)


def remove_rules_to_json(rules: list[RemoveRule]) -> str:
    """Serialize RemoveRule objects to JSON for the C helper."""
    out = []
    for r in rules:
        if r.op == 'remove_allow':
            out.append({"op": "remove_allow",
                        "src": r.src, "tgt": r.tgt, "cls": r.cls, "perms": r.perms})
        elif r.op == 'remove_genfscon':
            # Reuse src=fs_type, tgt=path
            out.append({"op": "remove_genfscon", "src": r.src, "tgt": r.tgt})
        elif r.op == 'remove_permissive':
            out.append({"op": "remove_permissive", "type": r.type_name})
        # remove_type and remove_typeattribute are CIL-only, not sent to binary helper
    return json.dumps(out, indent=2)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Neverallow conflict detection and CIL rewriting
# ---------------------------------------------------------------------------
#
# Background
# ----------
# In Android sepolicy, `neverallow` rules are compile-time assertions.  They
# are checked by `secilc` (and `checkpolicy`) when CIL is compiled to a
# kernel-format binary, then DISCARDED — they never enter the runtime binary
# and the kernel never enforces them.  The runtime kernel only enforces
# `allow` rules.
#
# This means that injecting a new `allow` rule into a precompiled binary
# policy "just works" at runtime, even when the rule violates a neverallow
# in the CIL source.  The risk only materialises if `init` ever recompiles
# from CIL — which it does whenever the precompiled binary's SHA-256 sidecar
# disagrees with the CIL hash.  At that point `secilc` will fail to compile
# the policy and the device may fall back to a clean policy without the
# injected rules, or fail to boot.
#
# This module makes the tool aware of CIL neverallow rules so it can:
#   1. Detect when a proposed `allow` rule conflicts with an existing CIL
#      neverallow.
#   2. Prompt the user.
#   3. On consent, comment out the original neverallow and write a rewritten
#      version below it with the offending permission(s) dropped (or, if the
#      conflict is structural, with the offending source subtracted).
#
# Scope
# -----
# Three CIL files are processed where they exist (matching the partitions
# whose binary policies are already patched by this tool):
#   - system/.../plat_sepolicy.cil
#   - vendor/.../vendor_sepolicy.cil
#   - system_ext/.../system_ext_sepolicy.cil
#
# The --plat-cil-only flag restricts processing to plat_sepolicy.cil only.

# (re already imported by main script)
# (shutil already imported by main script)
# (sys already imported by main script)
# (tempfile already imported by main script)
import time
# (dataclass/field already imported)
# (Path already imported)
# (Optional already imported)


@dataclass
class CilNeverallow:
    """A single (neverallow ...) statement parsed from a CIL file.

       When this neverallow was already rewritten by a prior sepinject run,
       `previously_rewritten` is True and the auxiliary metadata below is
       populated.  In that case the `src_expr`/`tgt_expr`/`cls`/`perms`
       fields reflect the ORIGINAL (pre-rewrite) neverallow, recovered from
       the `;; (neverallow ...)` audit comment above the live aux-based
       neverallow line.  This is what allows the conflict detector to
       recognize that a brand-new allow rule violates the SAME original
       neverallow that a previous run already carved out for a different
       domain — instead of detecting a fresh conflict against the
       rewritten aux-based line, which would cascade into a nested
       sepinject_aux_sepinject_aux_* rewrite that does not compile.
    """
    cil_path: Path
    line_no: int            # 1-based line in the source file.  For a normal
                            # neverallow this is the literal `(neverallow ...)`
                            # line.  For a previously-rewritten neverallow this
                            # is the LIVE aux-based `(neverallow sepinject_aux_*)`
                            # line (so the rewriter operates on the active line).
    raw_line: str           # exact text of the line, including trailing \n if present.
                            # For previously-rewritten neverallows this is the
                            # ORIGINAL (recovered) neverallow text, not the live
                            # aux-based line — the rewriter uses raw_line as the
                            # canonical form when building a fresh carve-out from
                            # baseline, and uses live_raw_line for the line to
                            # comment out.
    src_expr: str           # raw S-expression for the source (e.g. "appdomain" or "(and (a) (not (b)))")
    tgt_expr: str           # raw S-expression for the target
    cls: str                # class name (e.g. "file")
    perms: list             # list of permission names (e.g. ["read","write"])

    # ---- Sepinject-block metadata (set only when previously_rewritten=True) ----
    previously_rewritten: bool = False
    aux_name: Optional[str] = None        # name of the existing sepinject_aux_* attribute
    original_line_no: Optional[int] = None  # line of the `;; (neverallow ORIG ...)` comment
    live_raw_line: Optional[str] = None     # exact text of the live `(neverallow sepinject_aux_*)` line
    prior_excluded_srcs: list = field(default_factory=list)  # domains already exempted by the existing aux
    triggers_text: Optional[str] = None     # the `;; sepinject: triggered by: ...` audit line text
    rewrite_block_line_nos: set = field(default_factory=set)  # all line numbers in the block (audit + live)


@dataclass
class NeverallowConflict:
    """A detected conflict between a proposed allow rule and an existing neverallow."""
    rule: 'TeRule'                  # the proposed allow rule
    neverallow: CilNeverallow       # the matching neverallow
    matched_perms: list             # list of perm names from rule.perms that the neverallow covers
    structural: bool                # True if the rule's class fully matches but with all perms; False if specific perms
    # Resolved type set of neverallow.src_expr against the global attr_map.
    # None means the expression was too complex to fully resolve (caller should
    # treat as potentially-non-empty — conservative).  Used by build_rewrite to
    # detect vacuous carve-outs without re-running the resolver.
    src_resolved: Optional[set] = None
    # Note on the rewrite strategy choice:
    #   The new default (post-functionality-change) is the carve-out path:
    #   build a sepinject_aux_* attribute that subtracts the offending
    #   source domain(s) from the neverallow's source set.  This is the
    #   narrower, security-preserving option — only the specific allow
    #   target is exempted; the neverallow remains in effect for every
    #   other domain in its original source set.
    #
    #   The perm-drop path (rewrite the neverallow with matched perms
    #   removed) is now only used as a fallback when the carve-out would
    #   be vacuous (i.e. the neverallow's resolved source set is entirely
    #   contained in the set of sources being exempted, so subtracting
    #   them leaves the empty set).
    #
    #   When BOTH would be vacuous (every perm is also matched), the
    #   rewriter emits an explanatory comment instead of writing a
    #   no-op neverallow.  The `structural` field is kept for
    #   informational use but no longer steers the strategy.


# ----- S-expression tokenizer / parser (minimal, for CIL fragments) -----

def _na_tokenize_sexpr(s: str) -> list:
    """Tokenize a CIL S-expression string.  Returns flat list of tokens:
       '(', ')', or a bare atom string.  Whitespace is the separator outside
       of parens.  CIL has no string literals in the contexts we parse here."""
    tokens = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == '(' or c == ')':
            tokens.append(c)
            i += 1
            continue
        # atom
        j = i
        while j < n and not s[j].isspace() and s[j] not in '()':
            j += 1
        tokens.append(s[i:j])
        i = j
    return tokens


def _na_parse_sexpr(tokens: list, pos: int = 0):
    """Parse a single S-expression from tokens starting at pos.
       Returns (parsed_value, next_pos).  An atom is returned as a string,
       a list expression as a Python list of parsed children."""
    if pos >= len(tokens):
        return None, pos
    tok = tokens[pos]
    if tok == '(':
        pos += 1
        children = []
        while pos < len(tokens) and tokens[pos] != ')':
            child, pos = _na_parse_sexpr(tokens, pos)
            children.append(child)
        if pos < len(tokens):
            pos += 1  # consume ')'
        return children, pos
    elif tok == ')':
        # Shouldn't happen at top-level callsite
        return None, pos + 1
    else:
        return tok, pos + 1


def _na_parse_sexpr_one(s: str):
    """Parse a single top-level S-expression from a string.  Returns the
       parsed value (string atom or list)."""
    tokens = _na_tokenize_sexpr(s)
    if not tokens:
        return None
    val, _ = _na_parse_sexpr(tokens, 0)
    return val


# ----- CIL extraction: collect neverallows and typeattributeset definitions -----

def parse_cil_neverallows(cil_path: Path) -> list:
    """Walk a CIL file line-by-line and extract every top-level
       (neverallow ...) statement.

       In AOSP-generated plat_sepolicy.cil the neverallow blocks are always
       single-line, e.g.:
         (neverallow base_typeattr_1 domain (process (fork)))
       or:
         (neverallow appdomain rootfs (file (write create ...)))
       This function assumes single-line form, which holds for every neverallow
       observed in real AOSP-generated CIL output.  Multi-line forms (if any
       appear in vendor CILs) are skipped with a warning so the user knows
       the scan was incomplete.

       Idempotency note: this script's neverallow rewriter comments out the
       original line with a `;; sepinject:` marker and writes a relaxed
       version below.  On a subsequent run, the commented-out original
       must NOT be re-parsed as a live neverallow — otherwise we'd
       generate phantom conflicts for rules that were already exempted.
       In practice CIL comments (lines starting with ';') don't match
       the '(neverallow ' prefix below, so they're already skipped — but
       we add an explicit comment-skip at the top of the loop for clarity
       and to defend against any future formatting changes.

       Returns a list of CilNeverallow objects.
    """
    if not cil_path.exists():
        return []

    results = []
    skipped = 0
    text = cil_path.read_text(errors='replace')
    lines = text.splitlines(keepends=True)

    # ---- First pass: identify sepinject blocks ----
    # A sepinject block is the multi-line audit trail left by a previous
    # rewrite run, structured like:
    #
    #   ;; sepinject: commented (neverallow rewritten below)
    #   ;; (neverallow ORIG_SRC ORIG_TGT (CLS (PERM ...)))
    #   ;; sepinject: triggered by: allow D1 tgt:cls {perm}[, allow D2 ...]
    #   (neverallow sepinject_aux_<name>_<hash> ORIG_TGT (CLS (PERM ...)))
    #
    # We need to recognize this whole block as referring to the ORIGINAL
    # neverallow (recovered from the `;;` commented line) — not the live
    # aux-based line — so that a fresh allow rule for a DIFFERENT domain
    # is detected as conflicting with the same original neverallow and
    # we extend the existing carve-out instead of cascading a new one
    # on top of the rewritten line.
    sepinject_blocks = _find_sepinject_blocks(lines)
    # sepinject_blocks: dict { live_line_no (1-based) -> block_info }
    #   block_info keys: original_line_no, original_text, aux_name,
    #                    triggers_text, block_line_nos (set)

    # Set of all line numbers belonging to any sepinject block (audit
    # comments + the live aux-based line).  Used to skip these lines
    # during the main parse loop so we don't accidentally double-emit.
    sepinject_block_lines: set = set()
    for b in sepinject_blocks.values():
        sepinject_block_lines.update(b['block_line_nos'])

    for idx, raw_line in enumerate(lines, start=1):
        # ---- Handle sepinject-block live lines specially ----
        # When this idx is the live `(neverallow sepinject_aux_*)` line of
        # a previously-applied rewrite, emit a CilNeverallow built from
        # the ORIGINAL (recovered) text — flagged with previously_rewritten=True
        # so the rewriter knows to extend the existing aux instead of
        # cascading a new rewrite on top.
        if idx in sepinject_blocks:
            block = sepinject_blocks[idx]
            sexpr = _na_parse_sexpr_one(block['original_text'])
            if not (isinstance(sexpr, list) and len(sexpr) >= 4
                    and sexpr[0] == 'neverallow'):
                # Recovery failed — fall through and parse the live line as
                # a normal neverallow so the user still gets some coverage,
                # but warn so the situation is visible.
                print(f"  [!] {cil_path.name}:{idx} sepinject block detected "
                      f"but could not recover original neverallow text "
                      f"({block.get('original_text','')!r}) — treating live "
                      f"aux line as a fresh neverallow.  Manual review "
                      f"recommended.")
            else:
                src_node = sexpr[1]
                tgt_node = sexpr[2]
                cls_perms_node = sexpr[3]
                if (isinstance(cls_perms_node, list)
                        and len(cls_perms_node) == 2
                        and isinstance(cls_perms_node[0], str)):
                    cls_name = cls_perms_node[0]
                    perms_node = cls_perms_node[1]
                    if isinstance(perms_node, str):
                        perms = [perms_node]
                    elif isinstance(perms_node, list):
                        perms = [p for p in perms_node if isinstance(p, str)]
                    else:
                        perms = None
                    if perms is not None:
                        src_str = _na_sexpr_to_str(src_node)
                        tgt_str = _na_sexpr_to_str(tgt_node)
                        results.append(CilNeverallow(
                            cil_path=cil_path,
                            line_no=idx,                # live line to comment out
                            raw_line=block['original_text'],  # canonical original form
                            src_expr=src_str,
                            tgt_expr=tgt_str,
                            cls=cls_name,
                            perms=perms,
                            previously_rewritten=True,
                            aux_name=block['aux_name'],
                            original_line_no=block['original_line_no'],
                            live_raw_line=raw_line,
                            triggers_text=block.get('triggers_text'),
                            rewrite_block_line_nos=set(block['block_line_nos']),
                        ))
                        continue
            # Fall through to normal parse if recovery didn't yield a usable
            # original — but DO NOT skip block-internal lines below: the live
            # line will be handled by the normal parse path as a fresh
            # neverallow, which is the conservative fallback.

        # Skip ALL other lines belonging to a sepinject block (audit comments
        # and — when block recovery succeeded — the live line, which was
        # already emitted above via the `continue`).
        if idx in sepinject_block_lines:
            continue

        stripped = raw_line.lstrip()
        # Explicit comment skip — handles ;-prefixed CIL comments and the
        # ;; sepinject-marker comments we write during rewrite.  Without
        # this, a commented-out neverallow from a prior rewrite run could
        # in theory be misread as live, producing phantom conflicts.
        if not stripped or stripped.startswith(';'):
            continue
        # Match (neverallow followed by whitespace — exclude (neverallowx which
        # is a separate ioctl-extended-perm directive we don't handle here.
        if not (stripped.startswith('(neverallow ') or stripped.startswith('(neverallow\t')):
            continue
        # Verify the line is self-contained: parens balanced on this line.
        opens = raw_line.count('(')
        closes = raw_line.count(')')
        if opens != closes:
            skipped += 1
            continue
        # Parse the S-expression
        sexpr = _na_parse_sexpr_one(raw_line)
        if not isinstance(sexpr, list) or len(sexpr) < 4 or sexpr[0] != 'neverallow':
            skipped += 1
            continue
        # Form: (neverallow <src> <tgt> (<cls> (<perm1> <perm2> ...)))
        src_node = sexpr[1]
        tgt_node = sexpr[2]
        cls_perms_node = sexpr[3]
        if not isinstance(cls_perms_node, list) or len(cls_perms_node) != 2:
            skipped += 1
            continue
        cls_name = cls_perms_node[0]
        perms_node = cls_perms_node[1]
        if isinstance(perms_node, str):
            perms = [perms_node]
        elif isinstance(perms_node, list):
            perms = [p for p in perms_node if isinstance(p, str)]
        else:
            skipped += 1
            continue
        # Stringify src/tgt back to their raw CIL form for later substitution.
        src_str = _na_sexpr_to_str(src_node)
        tgt_str = _na_sexpr_to_str(tgt_node)
        if not isinstance(cls_name, str):
            skipped += 1
            continue
        results.append(CilNeverallow(
            cil_path=cil_path,
            line_no=idx,
            raw_line=raw_line,
            src_expr=src_str,
            tgt_expr=tgt_str,
            cls=cls_name,
            perms=perms,
        ))
    if skipped:
        print(f"  [~] {skipped} neverallow line(s) in {cil_path.name} skipped (multi-line or malformed)")
    if sepinject_blocks:
        print(f"  [i] {cil_path.name}: detected {len(sepinject_blocks)} "
              f"existing sepinject rewrite block(s) — will extend "
              f"existing carve-out(s) instead of cascading new ones if a "
              f"new conflict matches.")
    return results


# ----- Sepinject block detection -----
#
# A sepinject block is the multi-line audit trail a previous rewrite run
# leaves behind in a CIL file.  The canonical shape (as written by
# apply_neverallow_rewrites) is:
#
#     ;; sepinject: commented (neverallow rewritten below)
#     ;; (neverallow ORIG_SRC ORIG_TGT (CLS (PERMS)))
#     ;; sepinject: triggered by: allow D1 tgt:cls {perm}[, allow D2 ...]
#     (neverallow sepinject_aux_<inner>_minus_<excl>_<hash> ORIG_TGT (CLS (PERMS)))
#
# Older / extended forms may have additional `;;` audit lines (e.g. from
# the validate-repair workflow or from an earlier "extend" operation that
# layered more audit comments above the live line).  The recognizer is
# liberal: it identifies the block by the `;; sepinject: commented`
# header marker and walks forward over any `;;`-prefixed lines until the
# first non-comment line.  That first non-comment line is treated as the
# block's "live" line ONLY if it parses as `(neverallow sepinject_aux_* ...)`.

_SEPINJECT_HEADER_RE = re.compile(
    r'^\s*;;\s*sepinject:\s*commented\s*\(neverallow rewritten below\)',
)
_SEPINJECT_AUDIT_RE = re.compile(r'^\s*;;')
_SEPINJECT_TRIGGERED_BY_RE = re.compile(
    r'^\s*;;\s*sepinject:\s*triggered\s+by:\s*(.*)$',
)
_SEPINJECT_ORIG_NA_RE = re.compile(
    r'^\s*;;\s*(\(neverallow\b.*\))\s*$',
)
_SEPINJECT_LIVE_AUX_NA_RE = re.compile(
    r'^\s*\(neverallow\s+(sepinject_aux_[A-Za-z0-9_]+)\s',
)


def _find_sepinject_blocks(lines: list) -> dict:
    """Scan a CIL file's lines (as returned by splitlines(keepends=True))
       and return a dict mapping the 1-based line number of each live
       `(neverallow sepinject_aux_*)` line to a block_info dict.

       block_info keys:
         original_line_no: 1-based line of the `;; (neverallow ORIG ...)`
                           comment that holds the recovered original text.
                           None if not found.
         original_text:    The recovered `(neverallow ORIG ...)` text, with
                           the leading `;; ` stripped.  None if not found.
                           When multiple `;; (neverallow ...)` audit lines
                           exist in the block's `;;`-comment span (as
                           happens with the pre-fix cascade bug, which
                           stacked one rewrite block on top of the
                           previous one), we PREFER the earliest line
                           that does NOT reference any `sepinject_aux_*`
                           attribute — that's the true baseline.  This
                           lets --validate recover the original correctly
                           even from deeply-nested cascade artifacts.
         aux_name:         The sepinject_aux_* attribute name from the
                           live line's source position.
         triggers_text:    Concatenation of every `;; sepinject: triggered
                           by:` audit line in the block (joined by '; ')
                           so --validate can recover the full trigger
                           history across cascade levels.
         block_line_nos:   Set of 1-based line numbers spanned by the
                           block, INCLUDING the live aux-based neverallow
                           line.  Used by the caller to skip these during
                           the normal neverallow parse loop.

       Blocks whose live line cannot be parsed as a sepinject_aux_*
       neverallow are silently skipped (the audit comments alone do not
       constitute a complete block — the script will fall through and
       re-scan normally).
    """
    blocks: dict = {}
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        if not _SEPINJECT_HEADER_RE.match(line):
            i += 1
            continue
        # Found the START of a sepinject block.  The cascade bug stacked
        # one block on top of the previous one, so the "block" we care
        # about is the entire SPAN of consecutive `;;`-comment lines that
        # begins with this header — possibly containing several more
        # `;; sepinject: commented` headers from previous buggy runs.
        block_start = i
        candidate_originals: list = []   # list of (1-based line_idx, text)
        triggers_texts: list = []
        j = i
        while j < n and _SEPINJECT_AUDIT_RE.match(lines[j]):
            l = lines[j]
            m_orig = _SEPINJECT_ORIG_NA_RE.match(l)
            if m_orig:
                candidate_originals.append((j + 1, m_orig.group(1)))
            m_trig = _SEPINJECT_TRIGGERED_BY_RE.match(l)
            if m_trig:
                triggers_texts.append(m_trig.group(1).rstrip())
            j += 1
        # j now points at the first non-`;;` line OR past EOF.
        if j >= n:
            # No live line — incomplete block.  Skip the whole span.
            i = j
            continue
        live_line = lines[j]
        m_live = _SEPINJECT_LIVE_AUX_NA_RE.match(live_line)
        if not m_live:
            # First non-comment line isn't a sepinject_aux_* neverallow;
            # not a complete block.  Advance past the header and keep
            # looking — there may be another header later.
            i = block_start + 1
            continue
        aux_name = m_live.group(1)
        live_line_idx = j  # 0-based
        # Pick the baseline original: prefer the FIRST candidate that
        # does NOT reference any sepinject_aux_* attribute (that's the
        # pre-cascade-bug truth).  Fall back to the first candidate
        # otherwise — the caller can still detect that the recovered
        # text is a cascade artifact (it'll contain 'sepinject_aux_')
        # and treat the block as unrecoverable or
        # cascade-rebuilt-from-the-deepest-truth.
        original_line_no = None
        original_text = None
        for cand_idx, cand_text in candidate_originals:
            if 'sepinject_aux_' not in cand_text:
                original_line_no = cand_idx
                original_text = cand_text
                break
        if original_text is None and candidate_originals:
            original_line_no, original_text = candidate_originals[0]
        # Concatenate all triggered-by lines so the validator can recover
        # the full trigger history across cascade levels.
        triggers_text = '; '.join(triggers_texts) if triggers_texts else None
        block_line_nos = set(range(block_start + 1, live_line_idx + 2))
        blocks[live_line_idx + 1] = {
            'original_line_no': original_line_no,
            'original_text':    original_text,
            'aux_name':         aux_name,
            'triggers_text':    triggers_text,
            'block_line_nos':   block_line_nos,
        }
        i = j + 1
    return blocks


def _parse_aux_typeattributeset(node) -> tuple:
    """Extract the inner expression and the excluded-source list from a
       parsed typeattributeset body of the form `(and INNER (not EXCL))`.

       Accepts the body node (i.e. the S-expression that comes after the
       attribute name in `(typeattributeset NAME BODY)`).

       Returns (inner_expr_text, excluded_srcs_list) on success, or
       (None, None) if the body does not match the expected shape.

       Examples:
         (and (X) (not (D1)))            -> ('(X)', ['D1'])
         (and (X) (not (D1 D2 D3)))      -> ('(X)', ['D1','D2','D3'])
         (and X (not (D1)))              -> ('X',   ['D1'])
    """
    if not isinstance(node, list) or len(node) != 3 or node[0] != 'and':
        return (None, None)
    inner = node[1]
    not_clause = node[2]
    if not (isinstance(not_clause, list) and len(not_clause) == 2
            and not_clause[0] == 'not'):
        return (None, None)
    excl_node = not_clause[1]
    if isinstance(excl_node, str):
        excluded = [excl_node]
    elif isinstance(excl_node, list):
        excluded = [e for e in excl_node if isinstance(e, str)]
    else:
        return (None, None)
    inner_text = _na_sexpr_to_str(inner)
    return (inner_text, excluded)


def _na_sexpr_to_str(node) -> str:
    """Convert a parsed S-expression back to its compact text form."""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return '(' + ' '.join(_na_sexpr_to_str(c) for c in node) + ')'
    return ''


def parse_cil_typeattributesets(cil_path: Path) -> dict:
    """Extract every (typeattributeset ATTR_NAME EXPR) statement from a CIL
       file.  Returns a dict mapping attribute name -> raw S-expression node
       (string atom or list).  Multiple typeattributeset entries for the same
       attribute are merged with an implicit 'or'.

       Like parse_cil_neverallows, assumes single-line form.
    """
    if not cil_path.exists():
        return {}

    result: dict = {}
    text = cil_path.read_text(errors='replace')
    for raw_line in text.splitlines():
        stripped = raw_line.lstrip()
        if not stripped.startswith('(typeattributeset'):
            continue
        if raw_line.count('(') != raw_line.count(')'):
            continue
        sexpr = _na_parse_sexpr_one(raw_line)
        if not isinstance(sexpr, list) or len(sexpr) < 3 or sexpr[0] != 'typeattributeset':
            continue
        attr_name = sexpr[1]
        if not isinstance(attr_name, str):
            continue
        expr = sexpr[2]
        if attr_name in result:
            # merge: (or existing new)
            result[attr_name] = ['or', result[attr_name], expr]
        else:
            result[attr_name] = expr
    return result


# ----- Attribute set resolution (expand attributes to concrete type sets) -----

def _na_resolve_set(expr, attr_map: dict, all_types: set, visiting: Optional[set] = None) -> Optional[set]:
    """Resolve a CIL set expression to a concrete set of type names.

       expr is a parsed S-expression (string atom or list).
       attr_map maps attribute names -> their raw definition expressions.
       all_types is the universe of all type/attribute names (used for 'all'
       and complement-handling).
       visiting is the recursion-guard set of attributes currently on the stack.

       Returns a set of type-name strings, or None if the expression is too
       complex to fully resolve (in which case the caller treats it as
       potentially-matching everything — conservative).
    """
    if visiting is None:
        visiting = set()

    if isinstance(expr, str):
        # Atom: either a type, attribute, or special keyword
        if expr == 'self':
            return {'__SELF__'}
        if expr == 'all':
            return set(all_types)
        if expr in attr_map:
            if expr in visiting:
                # cycle — bail out conservatively
                return None
            visiting.add(expr)
            r = _na_resolve_set(attr_map[expr], attr_map, all_types, visiting)
            visiting.discard(expr)
            return r
        # Plain type (or attribute we don't have a definition for — treat as opaque)
        return {expr}

    if not isinstance(expr, list) or not expr:
        return None

    op = expr[0]
    args = expr[1:]

    # If the first element isn't a recognized operator keyword, treat the
    # whole list as a bare set of atoms (implicit 'or').  CIL frequently uses
    # this form, e.g. (typeattributeset appdomain (bluetooth shell ...)).
    if op not in ('and', 'or', 'not', 'xor', 'all'):
        # Treat the entire list as an implicit union of its elements.
        result = set()
        for a in expr:
            s = _na_resolve_set(a, attr_map, all_types, visiting)
            if s is None:
                return None
            result |= s
        return result

    if op == 'and':
        if not args:
            return set()
        first = _na_resolve_set(args[0], attr_map, all_types, visiting)
        if first is None:
            return None
        result = set(first)
        for a in args[1:]:
            s = _na_resolve_set(a, attr_map, all_types, visiting)
            if s is None:
                return None
            result &= s
        return result

    if op == 'or':
        result = set()
        for a in args:
            s = _na_resolve_set(a, attr_map, all_types, visiting)
            if s is None:
                return None
            result |= s
        return result

    if op == 'not':
        # 'not' inside an 'and' context means complement-within-universe.
        # We handle it by returning all_types - resolved(args).
        if not args:
            return set()
        inner = _na_resolve_set(args[0], attr_map, all_types, visiting)
        if inner is None:
            return None
        return set(all_types) - inner

    if op == 'xor':
        # rare but defined in CIL
        if len(args) < 2:
            return None
        a = _na_resolve_set(args[0], attr_map, all_types, visiting)
        b = _na_resolve_set(args[1], attr_map, all_types, visiting)
        if a is None or b is None:
            return None
        return a ^ b

    # Single-element list, e.g. ((appdomain)) — common in CIL — unwrap.
    if len(expr) == 1:
        return _na_resolve_set(expr[0], attr_map, all_types, visiting)

    return None


def collect_all_type_names(cil_path: Path) -> set:
    """Best-effort scan to collect every type and attribute name declared
       in the CIL file.  Used as the universe for complement operations.

       Looks for (type NAME), (typeattribute NAME), and (typeattributeset
       NAME ...) declarations.  This is approximate — it doesn't see types
       declared in mapping files — but it's enough for conservative
       conflict detection.
    """
    if not cil_path.exists():
        return set()
    names = set()
    text = cil_path.read_text(errors='replace')
    pat = re.compile(r'^\s*\(\s*(type|typeattribute|typeattributeset)\s+([A-Za-z_][\w]*)\b')
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            names.add(m.group(2))
    return names


# ----- Conflict detection -----

def _augment_attrmap_and_types_with_rules(rules: list,
                                           attr_map: dict,
                                           all_types: set) -> tuple:
    """Extend `attr_map` and `all_types` with types/attributes that the
       caller-supplied rules will introduce on this run.

       Why this matters: the scanner reads attr_map and all_types from the
       CIL file as it stands BEFORE patches are applied.  When the user adds
       a new domain (e.g. `type pit_installer, domain;`), the rule that puts
       pit_installer in the `domain` attributeset is in the rule list, not in
       the CIL yet.  Without this augmentation, the scanner resolves
       `(neverallow domain ...)` to a `domain` set that doesn't include
       pit_installer — so it misses every conflict involving the new type.

       At runtime, init's CIL compile concatenates the user's additions
       with the existing CIL before resolving attribute membership.  Our
       scanner needs to do the same.

       Returns (augmented_attr_map, augmented_all_types).  Both are shallow
       copies; caller-supplied originals are left untouched.
    """
    aug_attr_map = dict(attr_map)
    aug_all_types = set(all_types)

    # Helper to add member to attr_map[attr_name]'s members
    def add_member(attr_name: str, member: str):
        existing = aug_attr_map.get(attr_name)
        # Existing may be an S-expression node (list) or absent.
        # We append by wrapping in a synthetic union: (or existing (member))
        if existing is None:
            aug_attr_map[attr_name] = [member]
        elif isinstance(existing, list):
            # If it's already a flat list of atoms, just append
            if all(isinstance(x, str) for x in existing):
                if member not in existing:
                    aug_attr_map[attr_name] = existing + [member]
            else:
                # Wrap in a union: ['or', existing, member]
                aug_attr_map[attr_name] = ['or', existing, member]
        else:
            # Scalar existing -> turn into list
            aug_attr_map[attr_name] = [existing, member] if existing != member else [existing]

    for r in rules:
        if r.op == 'type' and r.type_name:
            aug_all_types.add(r.type_name)
            if r.attr:
                add_member(r.attr, r.type_name)
        elif r.op == 'attribute' and r.type_name:
            aug_all_types.add(r.type_name)
        elif r.op == 'typeattribute' and r.type_name and r.attr:
            aug_all_types.add(r.type_name)
            add_member(r.attr, r.type_name)

    return aug_attr_map, aug_all_types


def find_neverallow_conflicts(rules: list, cil_paths: list) -> tuple:
    """For each `allow` rule in `rules`, scan all neverallows across the given
       CIL files and return any conflicts.

       cil_paths is a list of (label, Path) tuples; only Paths that exist are
       processed.

       A conflict exists when ALL of:
         - rule.src ∈ resolve(neverallow.src_expr)
         - rule.tgt ∈ resolve(neverallow.tgt_expr)  (or 'self' handling)
         - rule.cls == neverallow.cls
         - any p ∈ rule.perms that is also in neverallow.perms

       Important: the attribute membership map is built by MERGING entries
       from every CIL file we scan, so attribute memberships defined in
       plat_sepolicy.cil (e.g. `system_file in system_file_type`) are
       visible when resolving neverallows in plat_pub_versioned.cil that
       reference those attributes.  Without merging, file-local resolution
       can fail to match a target type to its containing attribute set,
       silently missing real conflicts.

       Also augmented with the rules being processed, so a new type
       declared as `type X, domain;` is correctly seen as a member of
       `domain` even before the CIL file contains that membership.

       Returns a tuple (conflicts, attr_map, all_types) where:
         - conflicts is the list of NeverallowConflict objects (each
           already has its `src_resolved` field populated with the
           resolved type set of the neverallow's source expression).
         - attr_map is the merged global attribute -> definition map.
         - all_types is the set of every type/attribute name seen.

       attr_map and all_types are returned so callers (e.g. build_rewrite)
       can perform the vacuity check needed to fix the empty-carve-out
       bug, where the resolved source set of a base_typeattr_NNN happens
       to be exactly the set being exempted.  Without resolving on both
       sides, a string-name compare misses that case and emits an
       empty-set typeattributeset that silently neuters the neverallow.
    """
    conflicts = []

    # ---- Build a GLOBAL attr_map and all_types from every CIL file ----
    # This matches how `secilc` actually resolves attribute memberships at
    # compile time: it sees all CIL files as one combined input.
    global_attr_map: dict = {}
    global_all_types: set = set()
    for _, cil_path in cil_paths:
        if not cil_path or not cil_path.exists():
            continue
        local_map = parse_cil_typeattributesets(cil_path)
        local_types = collect_all_type_names(cil_path)
        global_all_types.update(local_types)
        for attr_name, expr in local_map.items():
            if attr_name not in global_attr_map:
                global_attr_map[attr_name] = expr
            else:
                # Multiple definitions of the same attribute set across files —
                # union them. CIL semantics: (typeattributeset X ...) statements
                # combine via union, so we represent that as ['or', existing, new].
                existing = global_attr_map[attr_name]
                global_attr_map[attr_name] = ['or', existing, expr]

    # Now augment with rules being added in this run
    global_attr_map, global_all_types = _augment_attrmap_and_types_with_rules(
        rules, global_attr_map, global_all_types)

    # ---- Resolve prior_excluded_srcs for previously-rewritten neverallows ----
    # We need to know which domains the existing sepinject_aux_* attribute
    # already exempts so that:
    #   (a) we can skip conflicts whose rule.src is already in that set
    #       (avoids phantom conflicts on re-runs with the same rule);
    #   (b) the rewriter can merge the new exemption with the existing
    #       ones into a single extended carve-out.
    # The aux's typeattributeset may live in a different CIL file than the
    # neverallow, so the lookup uses the GLOBAL attr_map built above.
    # We do this lookup once, up-front, and stash the result on each
    # CilNeverallow object before the per-rule conflict loop.
    def _resolve_prior_exclusions(na: 'CilNeverallow') -> list:
        if not na.previously_rewritten or not na.aux_name:
            return []
        expr = global_attr_map.get(na.aux_name)
        if expr is None:
            return []
        # Walk the expression for (and INNER (not EXCL)) shape.  When
        # multiple typeattributeset definitions for the same aux name were
        # merged into ('or', a, b), we look at every leaf — but in practice
        # sepinject only ever emits one typeattributeset per aux, so the
        # common path is a direct match.
        candidates = [expr]
        excluded: list = []
        while candidates:
            n_ = candidates.pop()
            if isinstance(n_, list) and len(n_) >= 1 and n_[0] == 'or':
                candidates.extend(n_[1:])
                continue
            inner_text, excl = _parse_aux_typeattributeset(n_)
            if excl is not None:
                for e in excl:
                    if e not in excluded:
                        excluded.append(e)
        return excluded

    for label, cil_path in cil_paths:
        if not cil_path or not cil_path.exists():
            continue
        print(f"  [*] Scanning {label}: {cil_path.name}")
        neverallows = parse_cil_neverallows(cil_path)
        if not neverallows:
            print(f"      no neverallows parsed")
            continue
        print(f"      {len(neverallows)} neverallow(s) found")
        # Populate prior_excluded_srcs on every previously-rewritten
        # neverallow now that the global attr_map is built.  This lets
        # the conflict loop below filter out rules whose source is
        # already exempted (preventing phantom conflicts on re-run with
        # the same input) and lets the rewriter merge new exclusions
        # with the existing ones in a single extended carve-out.
        for na in neverallows:
            if na.previously_rewritten and not na.prior_excluded_srcs:
                na.prior_excluded_srcs = _resolve_prior_exclusions(na)
        # Use the global maps for resolution (covers cross-file attribute references)
        attr_map = global_attr_map
        all_types = global_all_types

        # Cache resolved src/tgt sets per neverallow to avoid re-resolving
        # for every rule.
        resolved_cache: dict = {}

        for rule in rules:
            if rule.op != 'allow':
                continue
            if not rule.cls or not rule.perms:
                continue
            for na in neverallows:
                # Class must match
                if na.cls != rule.cls:
                    continue
                # Perms intersection
                matched = [p for p in rule.perms if p in na.perms]
                if not matched:
                    continue
                # If this is a previously-rewritten neverallow and the
                # rule's source is already in the existing aux's exempted
                # set, there is nothing to do — the rewritten neverallow
                # already permits this domain.  Skipping here avoids
                # producing a phantom "extend" rewrite on a re-run with
                # the same input.
                if na.previously_rewritten and rule.src in na.prior_excluded_srcs:
                    continue
                # Resolve sources/targets (cached per neverallow)
                key = id(na)
                if key in resolved_cache:
                    src_set, tgt_set = resolved_cache[key]
                else:
                    src_expr_parsed = _na_parse_sexpr_one(na.src_expr) \
                        if na.src_expr.startswith('(') else na.src_expr
                    tgt_expr_parsed = _na_parse_sexpr_one(na.tgt_expr) \
                        if na.tgt_expr.startswith('(') else na.tgt_expr
                    src_set = _na_resolve_set(src_expr_parsed, attr_map, all_types)
                    tgt_set = _na_resolve_set(tgt_expr_parsed, attr_map, all_types)
                    resolved_cache[key] = (src_set, tgt_set)

                # Conservative: if we can't resolve, assume it might match
                src_match = (src_set is None) or (rule.src in src_set)
                if rule.tgt == 'self':
                    # 'self' target means src==tgt at runtime; conservative match
                    tgt_match = True
                else:
                    tgt_match = (tgt_set is None) or (rule.tgt in tgt_set)

                if src_match and tgt_match:
                    # Structural = all of the rule's requested perms are covered
                    structural = all(p in na.perms for p in rule.perms) and \
                                 len(matched) == len(rule.perms)
                    conflicts.append(NeverallowConflict(
                        rule=rule,
                        neverallow=na,
                        matched_perms=matched,
                        structural=structural,
                        # Cache the resolved source set so build_rewrite can
                        # detect a vacuous carve-out without re-running the
                        # resolver.  May be None if the source expression was
                        # too complex to fully resolve — in that case the
                        # rewriter treats it conservatively as non-empty.
                        src_resolved=src_set,
                    ))

    return conflicts, global_attr_map, global_all_types


# ----- Rewrite generation -----

def _make_aux_attr_name(inner_src: str, excluded_srcs) -> str:
    """Generate a deterministic, readable name for the auxiliary attribute used
       when subtracting one or more domains from a neverallow's source set.

       `excluded_srcs` may be either a single string (the legacy single-domain
       carve-out) or a list/iterable of strings (the multi-domain carve-out
       used when multiple proposed allow rules conflict with the same
       neverallow line).

       Stability matters: re-running the tool MUST produce the same aux
       name for the same (inner_src, excluded_srcs) inputs so we don't
       end up with multiple redundant declarations on a second run.  We
       normalize whitespace, sort the excluded list, and hash a portion
       to keep names unique for arbitrary expressions.

       Backwards compatibility: when called with a single-string excluded
       source (or a one-element list), the hash input is identical to the
       legacy form, so previously-emitted aux names are preserved across
       upgrades.
    """
    if isinstance(excluded_srcs, str):
        excluded_list = [excluded_srcs]
    else:
        excluded_list = sorted({s for s in excluded_srcs if s})
    norm_inner = re.sub(r'\s+', '', inner_src).strip('()')
    # Preserve byte-for-byte legacy hash input when there's exactly one
    # excluded source — this keeps aux names stable across the
    # functionality change so re-runs against existing CIL don't
    # duplicate-declare attributes that an earlier run already wrote.
    if len(excluded_list) == 1:
        excl_str = re.sub(r'\s+', '', excluded_list[0])
    else:
        excl_str = '_'.join(re.sub(r'\s+', '', s) for s in excluded_list)
    h = hashlib.sha1(f"{norm_inner}~{excl_str}".encode()).hexdigest()[:6]
    safe_inner = re.sub(r'[^a-zA-Z0-9_]+', '_', norm_inner)[:32]
    safe_excl  = re.sub(r'[^a-zA-Z0-9_]+', '_', excl_str)[:24]
    return f"sepinject_aux_{safe_inner}_minus_{safe_excl}_{h}"


def _format_perms(perms: list) -> str:
    """Format a CIL perm-list.  ALWAYS wraps in parens, even for a single
       perm: secilc rejects '(file entrypoint)' and requires '(file (entrypoint))'.

       This was a long-standing bug in the original rewriter — single-perm
       neverallows came out malformed, and the only reason they ever 'worked'
       was that the precompiled binary was being loaded rather than the
       recompiled CIL.  Once CIL recompile is forced, secilc rejects them
       with 'Bad allow rule / Failed to build AST'.

       Defense in depth: each incoming perm token is normalized — surrounding
       parens, commas, and whitespace are stripped, and anything that does
       not match a CIL identifier is discarded with a warning.  This catches
       state-dependent upstream bugs where perms arrive wrapped like
       '(execute_no_trans)' or comma-tagged like 'read,'.  Both produce
       invalid CIL such as `(file (execute (execute_no_trans)))` or
       `(file (read, open, getattr))` which secilc rejects.
    """
    cleaned: list[str] = []
    perm_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
    for p in perms:
        token = str(p).strip().strip('()').strip(',').strip()
        if not token:
            continue
        if not perm_re.match(token):
            print(f"  [!] _format_perms: discarding malformed perm token: {p!r}")
            continue
        cleaned.append(token)
    return '(' + ' '.join(cleaned) + ')'


def build_rewrite(conflict, aux_registry: dict = None,
                  attr_map: dict = None, all_types: set = None,
                  excluded_srcs: Optional[list] = None,
                  aux_fingerprints: dict = None) -> str:
    """Construct the rewritten neverallow line.

       NEW strategy (changed from older 'drop matched perms first'
       behavior).  Strategy ordering — most security-preserving first:

         1. Carve-out (default).  Build (or reuse) a named auxiliary
            attribute that subtracts the offending source domain(s) from
            the neverallow's source set, and have the neverallow target
            that aux instead.  This is the narrower choice: every other
            domain originally covered by the neverallow stays covered.

            CIL form:
              (typeattribute aux_name)
              (typeattributeset aux_name (and (X) (not (D))))      ; one
              (typeattributeset aux_name (and (X) (not (D1 D2)))) ; many
              (neverallow aux_name TGT (CLS (PERMS)))

         2. Perm-drop (fallback).  Only used when the carve-out would
            be vacuous — i.e. the resolved type set of the neverallow's
            source expression is entirely contained in the set of
            sources being exempted, so subtracting them leaves the
            empty set.  In that case there is no "unique domain" to
            carve out narrowly; the offending source IS the entire
            constraint.  We instead drop the matched perms from the
            neverallow, leaving it in effect for any remaining perms.

         3. Refusal (explanatory comment).  When BOTH paths are
            vacuous — carve-out empty AND every neverallow perm is
            matched — there's nothing left to write that preserves
            any protection.  We emit a `;; sepinject:` comment
            explaining the situation; the caller has already
            commented out the original neverallow, so the net effect
            is that the protection is gone.  This is no worse than
            either rewrite, and the comment makes the situation
            auditable.

       Bug 1 fix — vacuity is checked against the *resolved* source
       set, not just a string compare of expressions.  The old guard
       missed cases where na.src_expr was something like
       `base_typeattr_209` whose resolved set happened to be exactly
       `{init}`; a string compare against `init` doesn't match, but
       the resulting `(and (base_typeattr_209) (not (init)))` is empty.
       Using the resolved set catches this.

       Parameters:
         conflict:        the NeverallowConflict to rewrite.  If
                          conflict.src_resolved is populated (it is,
                          when produced by find_neverallow_conflicts),
                          it's used for the vacuity check.
         aux_registry:    dict { aux_name: (decl_line, set_line) }.
                          New aux decls are added here so the caller
                          can emit them once.  May be None for preview.
         attr_map,
         all_types:       resolution context.  Used to resolve
                          excluded_srcs (in case any are themselves
                          attributes) and, if conflict.src_resolved is
                          missing, to resolve na.src_expr on the fly.
                          May be None for preview.
         excluded_srcs:   list of source domains to exempt in the
                          carve-out.  Defaults to [conflict.rule.src]
                          when None; callers that merged multiple
                          conflicts for one neverallow line pass the
                          union of their rule.src values.
         aux_fingerprints: dict { aux_name: set of (tgt, cls, perms)
                          fingerprints }.  Used by the caller to warn
                          when one aux attribute is shared by
                          substantively different rewrites (Bug 2).
                          Optional.
    """
    na = conflict.neverallow

    # ---- 1. Determine excluded sources (the domains being carved out) ----
    if excluded_srcs is None:
        excluded_srcs = [conflict.rule.src]
    # Dedupe, drop empties, sort — gives stable aux naming and stable
    # carve-out expression regardless of the caller's input order.
    excluded_unique = sorted({s for s in excluded_srcs if s})
    if not excluded_unique:
        # Degenerate input — nothing to exempt, can't do a carve-out.
        # Fall straight through to the perm-drop path.
        excluded_unique = []

    # ---- 2. Resolve the neverallow's source set ----
    # Prefer the cached value attached by find_neverallow_conflicts;
    # otherwise resolve here if we have a map.  May still be None
    # (unresolvable / too complex) — treated conservatively below.
    src_resolved = getattr(conflict, 'src_resolved', None)
    if src_resolved is None and attr_map is not None and all_types is not None:
        src_parsed = _na_parse_sexpr_one(na.src_expr) \
            if na.src_expr.lstrip().startswith('(') else na.src_expr
        src_resolved = _na_resolve_set(src_parsed, attr_map, all_types)

    # ---- 3. Resolve the excluded sources (handles attribute names) ----
    # If excluded_unique contains an attribute (rare for allow.src but
    # possible), we want to subtract its full membership.  This makes
    # the vacuity check robust against attribute-vs-type mismatches.
    excluded_resolved: Optional[set] = None
    if excluded_unique and attr_map is not None and all_types is not None:
        acc: set = set()
        all_resolved = True
        for s in excluded_unique:
            parsed = _na_parse_sexpr_one(s) if s.lstrip().startswith('(') else s
            r = _na_resolve_set(parsed, attr_map, all_types)
            if r is None:
                all_resolved = False
                break
            acc |= r
        excluded_resolved = acc if all_resolved else None
    elif excluded_unique:
        # No map available — treat names opaquely.  Good enough for the
        # common single-bare-domain case; the string-compare fallback
        # below handles the literal-identity scenario.
        excluded_resolved = set(excluded_unique)

    # ---- 4. Vacuity check for carve-out ----
    carveout_vacuous = False
    if not excluded_unique:
        # No exemptions to apply — carve-out is undefined/vacuous.
        carveout_vacuous = True
    elif src_resolved is not None and excluded_resolved is not None:
        # Authoritative: if every member of src_resolved is in
        # excluded_resolved, the difference is empty.
        if src_resolved.issubset(excluded_resolved):
            carveout_vacuous = True
    else:
        # Fast-path fallback (also catches the pre-Bug-1 simple case):
        # if na.src_expr is literally equal (modulo parens/whitespace)
        # to the sole excluded source, the carve-out is trivially empty.
        if len(excluded_unique) == 1:
            src_norm = na.src_expr.strip().lstrip('(').rstrip(')').strip()
            excl_norm = excluded_unique[0].strip().lstrip('(').rstrip(')').strip()
            if src_norm == excl_norm:
                carveout_vacuous = True

    # ---- 5a. Carve-out path (default) ----
    if not carveout_vacuous:
        aux_name = _make_aux_attr_name(na.src_expr, excluded_unique)
        if aux_registry is not None and aux_name not in aux_registry:
            # Ensure inner src is parenthesized for typeattributeset.
            inner = na.src_expr if na.src_expr.lstrip().startswith('(') \
                else f'({na.src_expr})'
            # Form the (not ...) clause.  For a single exempted source we
            # keep the historical `(not (D))` form so existing aux decls
            # match byte-for-byte.  For multiple, we use the implicit-
            # union form `(not (D1 D2 D3))` — CIL's set-expression
            # grammar treats a bare list inside (not ...) as a union
            # (same way `(typeattributeset X (a b c))` unions a b c).
            if len(excluded_unique) == 1:
                excl_clause = f'({excluded_unique[0]})'
            else:
                excl_clause = '(' + ' '.join(excluded_unique) + ')'
            aux_registry[aux_name] = (
                f'(typeattribute {aux_name})',
                f'(typeattributeset {aux_name} (and {inner} (not {excl_clause})))',
            )
        # Record fingerprint for Bug 2 collision warning.  A "fingerprint"
        # captures the substantive content of the rewrite: target, class,
        # and the perm set.  When the same aux name is paired with more
        # than one fingerprint, the caller surfaces a warning — sharing
        # is correct for the carve-out, but a malformed aux would break
        # every neverallow that uses it, so visibility matters.
        if aux_fingerprints is not None:
            fp = (na.tgt_expr, na.cls, tuple(sorted(na.perms)))
            aux_fingerprints.setdefault(aux_name, set()).add(fp)
        return (f"(neverallow {aux_name} {na.tgt_expr} "
                f"({na.cls} {_format_perms(na.perms)}))")

    # ---- 5b. Perm-drop fallback (carve-out vacuous) ----
    # "There is not a unique domain to carve out" — the neverallow's
    # source set is fully contained in what we'd exempt, so we have to
    # touch the neverallow itself.  Drop the matched perms; if any
    # perms remain, the neverallow keeps protecting them.
    remaining_perms = [p for p in na.perms if p not in conflict.matched_perms]
    if remaining_perms:
        return (f"(neverallow {na.src_expr} {na.tgt_expr} "
                f"({na.cls} {_format_perms(remaining_perms)}))")

    # ---- 5c. Refusal (both vacuous) ----
    # Carve-out would be empty AND every perm in the neverallow is
    # matched.  There is no rewrite that preserves any protection here;
    # we emit an audit-friendly comment.  The caller has already
    # commented out the original neverallow line, so the protection
    # is gone — but the user is informed and can review.
    return (f";; sepinject: cannot rewrite — neverallow source "
            f"({na.src_expr}) resolves entirely to the exempted "
            f"source(s) [{', '.join(excluded_unique) if excluded_unique else '<none>'}] "
            f"and every perm is matched by the proposed allow; "
            f"any rewrite would be vacuous. "
            f"Original allow: {conflict.rule.src} "
            f"{conflict.rule.tgt}:{conflict.rule.cls} "
            f"{{{' '.join(conflict.rule.perms)}}}")


# ----- Rollback session -----

class RollbackSession:
    """Snapshots files before modification.  On revert(), restores them all.
       On commit(), leaves the snapshot in place for manual recovery."""

    def __init__(self):
        self.session_dir = Path(tempfile.gettempdir()) / \
            f"sepinject-rollback-{sys.argv[0].split('/')[-1]}-" \
            f"{os.getpid()}-{int(time.time())}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots: list = []  # list of (original_path, snapshot_path)
        self.committed = False

    def snapshot(self, path: Path) -> None:
        """Take a snapshot of `path` if it exists and hasn't been snapshotted yet."""
        path = Path(path)
        if not path.exists():
            return
        if any(orig == path for orig, _ in self.snapshots):
            return  # already snapshotted

        # Mirror the path structure under session_dir, but sanitize it
        try:
            # Get the absolute path to avoid .. components
            abs_path = path.resolve()
            # Create a safe relative path by replacing problematic characters
            rel_parts = [part.replace(':', '_') for part in abs_path.parts if part not in ('/', '\\')]
            snap = self.session_dir.joinpath(*rel_parts)
        except Exception:
            # Fallback to simple path sanitization
            path_str = str(path)
            # Remove leading slashes and replace problematic characters
            safe_path = path_str.lstrip('/').replace(':', '_').replace('..', '_')
            snap = self.session_dir / safe_path

        snap.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, snap)
        self.snapshots.append((path, snap))

    def revert(self) -> None:
        """Restore every snapshotted file to its original location."""
        print(f"\n[!] Reverting {len(self.snapshots)} file(s) from rollback session...")
        for orig, snap in self.snapshots:
            try:
                shutil.copy2(snap, orig)
                print(f"  [-] Restored: {orig}")
            except Exception as e:
                print(f"  [!] Failed to restore {orig}: {e}")
        print(f"[!] Rollback complete. Snapshot dir retained: {self.session_dir}")

    def commit(self) -> None:
        """Mark the session as successful — snapshots are kept in place
           for manual recovery but no automatic revert will occur."""
        self.committed = True
        if self.snapshots:
            print(f"\n[*] Pre-run snapshot retained at: {self.session_dir}")
            print(f"    ({len(self.snapshots)} file(s) captured before modification)")


# ----- Conflict prompt -----

def prompt_neverallow_conflicts(conflicts: list, binary_findings: list) -> bool:
    """Display all detected conflicts and ask the user to proceed.
       Default on empty input is NO.  Returns True iff the user typed y/Y/yes."""
    print("\n" + "=" * 70)
    print(f"[!] {len(conflicts)} neverallow conflict(s) detected in CIL source")
    if binary_findings:
        print(f"[!] {len(binary_findings)} unexpected neverallow entry/entries in binary policy")
    print("=" * 70)

    for i, c in enumerate(conflicts, 1):
        rule = c.rule
        na = c.neverallow
        print(f"\n  Conflict {i}:")
        print(f"    Adding:    allow {rule.src} {rule.tgt}:{rule.cls} "
              f"{{ {' '.join(rule.perms)} }};")
        print(f"    Violates:  {na.raw_line.strip()}")
        print(f"    Source:    {na.cil_path}:{na.line_no}")
        print(f"    Matched:   perm(s) {{ {' '.join(c.matched_perms)} }} from neverallow")

        if na.previously_rewritten:
            # Extend path — show the existing carve-out + the merged result.
            print(f"    State:     existing sepinject carve-out in place")
            print(f"               aux={na.aux_name}")
            print(f"               already excluded: "
                  f"{{ {', '.join(na.prior_excluded_srcs)} }}")
            merged_excluded = sorted(set(na.prior_excluded_srcs) | {rule.src})
            # Vacuity check uses the ORIGINAL src_resolved against the
            # MERGED exclusion set.
            extend_vacuous = False
            if c.src_resolved is not None:
                if c.src_resolved.issubset(set(merged_excluded)):
                    extend_vacuous = True
            if extend_vacuous:
                print(f"    Rewrite:   (extend would EMPTY the carve-out — "
                      f"vacuity prompt will appear; ALL CAPS marker will be "
                      f"written either way)")
            else:
                print(f"    Rewrite:   (will EXTEND existing carve-out — new "
                      f"merged exclusion set: {{ {', '.join(merged_excluded)} }})")
            # Preview the actual rewrite line.
            preview_conflict = NeverallowConflict(
                rule=rule, neverallow=na,
                matched_perms=c.matched_perms,
                structural=c.structural,
                src_resolved=c.src_resolved,
            )
            rewrite = build_rewrite(preview_conflict,
                                    excluded_srcs=merged_excluded)
            print(f"    Proposed:  {rewrite}")
            continue

        # Predict the rewrite path the same way build_rewrite() does:
        # the new default is the carve-out (narrowly exempting the
        # offending source).  Perm-drop is the fallback when the
        # carve-out would be vacuous.  See build_rewrite() docstring
        # for the full strategy ordering.
        carveout_vacuous = False
        if c.src_resolved is not None:
            if c.src_resolved.issubset({rule.src}):
                carveout_vacuous = True
        else:
            # Resolution unavailable — use the string fallback.
            src_norm = na.src_expr.strip().lstrip('(').rstrip(')').strip()
            rsrc_norm = rule.src.strip().lstrip('(').rstrip(')').strip()
            if src_norm == rsrc_norm:
                carveout_vacuous = True
        if not carveout_vacuous:
            print(f"    Rewrite:   (will exempt '{rule.src}' from neverallow "
                  f"source via aux attribute — narrow carve-out)")
        else:
            remaining = [p for p in na.perms if p not in c.matched_perms]
            if remaining:
                print(f"    Rewrite:   (carve-out would be vacuous; "
                      f"will drop matched perm(s) from neverallow instead)")
            else:
                print(f"    Rewrite:   (both carve-out and perm-drop would "
                      f"be vacuous — will emit explanatory comment)")
        rewrite = build_rewrite(c)
        print(f"    Proposed:  {rewrite}")

    if binary_findings:
        print(f"\n  Binary policy neverallow findings (unusual for AOSP, possible MTK artifact):")
        for f in binary_findings:
            print(f"    {f}")
        print(f"\n  No binary modifications will be made — kernel does not enforce")
        print(f"  neverallow, so these findings are informational only.")

    print("\n" + "=" * 70)
    print("If you proceed:")
    print("  - The conflicting neverallow lines will be commented out in their CIL files")
    print("  - A rewritten version will be inserted immediately below each one")
    print("  - SHA-256 sidecars will be regenerated")
    print("If you decline:")
    print("  - All files modified so far this run will be reverted from snapshot")
    print("  - The tool will exit without applying any changes")
    print("=" * 70)

    try:
        answer = input("\nProceed with neverallow rewrites? [y/N]: ").strip().lower()
    except EOFError:
        answer = ''
    return answer in ('y', 'yes')


# ----- CIL file mutation -----

# Audit-comment markers used to leave a forensic trail in CIL files when
# an existing sepinject rewrite is modified (extended) to cover additional
# excluded domains.  These markers are detected on subsequent runs so the
# script does not double-process them.
_SEPINJECT_EXTEND_HEADER = ";; sepinject: superseded (extended carve-out below)\n"
_SEPINJECT_AUX_DEPRECATED_HEADER = ";; sepinject: aux decl deprecated (extended below)\n"
_SEPINJECT_VACUITY_BANNER = (
    ";; !!! SEPINJECT VACUITY WARNING !!! "
    "EXTENDING THIS CARVE-OUT WOULD LEAVE THE AUX EMPTY — "
    "REVIEW REQUIRED.\n"
)


def _prompt_vacuity_decision(na: 'CilNeverallow',
                             new_excluded: list,
                             merged_excluded: list,
                             remaining_perms: list) -> str:
    """Interactively ask the user how to handle a vacuity edge case when
       extending an existing carve-out would leave the aux empty.

       Returns one of:
         'extend'    — proceed with the extend anyway (will produce an
                       empty aux; ALL CAPS marker will be written above).
         'permdrop'  — fall back to perm-drop on the original neverallow,
                       comment out the existing live aux line, drop the
                       matched perms.  remaining_perms must be non-empty
                       for this to make sense; the prompt only offers it
                       when so.
         'skip'      — do nothing; leave the existing carve-out alone and
                       SKIP adding this new exemption.  ALL CAPS marker is
                       still written above the offending line so the
                       situation is auditable.
    """
    print("\n" + "!" * 70)
    print(f"[!] VACUITY WARNING: extending existing carve-out would empty it")
    print(f"!" * 70)
    print(f"  Neverallow:         {na.raw_line.strip()}")
    print(f"  File:               {na.cil_path}:{na.line_no}")
    print(f"  Aux attribute:      {na.aux_name}")
    print(f"  Already excluded:   {{ {', '.join(na.prior_excluded_srcs)} }}")
    print(f"  Now adding:         {{ {', '.join(new_excluded)} }}")
    print(f"  Merged excluded:    {{ {', '.join(merged_excluded)} }}")
    print(f"  Original src set:   resolves entirely to the merged exclusion list,")
    print(f"                      so (and (X) (not (merged))) is empty — the")
    print(f"                      neverallow would no longer constrain anything.")
    print()
    print("Options:")
    print("  [e] extend anyway — write empty-aux carve-out (marked with ALL CAPS warning)")
    if remaining_perms:
        print(f"  [p] perm-drop fallback — revert the aux rewrite, drop matched")
        print(f"      perm(s) from the original neverallow instead;")
        print(f"      remaining perms after drop: {{ {' '.join(remaining_perms)} }}")
    print("  [s] skip — leave existing carve-out unchanged, do NOT exempt the new domain(s)")
    print("            (the ALL CAPS warning is still written above the offending")
    print("             neverallow so this decision is auditable)")
    valid_opts = ('e', 'p', 's') if remaining_perms else ('e', 's')
    default = 's'
    while True:
        try:
            ans = input(f"\n  Decision [{'/'.join(valid_opts)}, default={default}]: ").strip().lower()
        except EOFError:
            ans = ''
        if not ans:
            ans = default
        if ans in valid_opts:
            if ans == 'e':
                return 'extend'
            if ans == 'p':
                return 'permdrop'
            return 'skip'
        print(f"  Invalid choice {ans!r}; please pick one of {valid_opts}.")


def apply_neverallow_rewrites(conflicts: list, rollback: RollbackSession,
                              all_cil_paths: list | None = None,
                              attr_map: dict | None = None,
                              all_types: set | None = None) -> dict:
    """Group conflicts by CIL file and apply the rewrites.  Each conflicting
       neverallow line is commented out (prefixed with ';; sepinject: ') and a
       rewritten version is inserted on the next line, prefixed with a marker
       comment for traceability.

       Rewrite strategy (see build_rewrite() for full detail):

         1. Default — narrow carve-out.  Build (or reuse) a
            sepinject_aux_* attribute that subtracts the offending
            source domain(s) from the neverallow's source set, and
            point the neverallow at that aux instead.  When multiple
            proposed allow rules conflict with the same neverallow
            line, the carve-out exempts the union of their source
            domains in one expression.

         2. Fallback — perm-drop.  Used only when the carve-out
            would be vacuous (the neverallow's resolved source set
            is fully contained in what we'd exempt).  In that case
            the matched perms are removed from the neverallow itself.

         3. Refusal — explanatory comment.  Used when both above
            paths would be vacuous.

       EXTEND PATH (new in this version):
         When a conflict's neverallow has `previously_rewritten=True` —
         i.e. a prior sepinject run already commented out the original
         neverallow and replaced it with a `(neverallow sepinject_aux_*)`
         line that carves out some prior set of domains — we MERGE the
         new exclusion(s) with the existing prior_excluded_srcs and
         emit a fresh aux + neverallow with the unioned exclusion list.
         The previous live aux-based neverallow line is commented out
         with a `;; sepinject: superseded (extended carve-out below)`
         audit header, and the previous aux's typeattribute /
         typeattributeset decls (when located in any file we're
         processing) are also commented out with a deprecation header.
         The original `;; (neverallow ORIG ...)` audit comment from the
         first run stays put so the lineage is fully traceable.

         Vacuity edge case: if merging the new exclusions with the prior
         exclusions would leave the aux's resolved source set empty
         (e.g. the original neverallow's source resolves to exactly
         {D1, D2} and D1 was already exempted), we PROMPT INTERACTIVELY
         and an ALL CAPS warning marker is written above the offending
         neverallow regardless of the user's choice.  See
         _prompt_vacuity_decision() for the options.

       Auxiliary attribute declarations are emitted at the bottom of the
       FIRST file that introduced them.  Since `secilc` combines all CIL
       files at compile time, a typeattribute declared in plat_sepolicy.cil
       is visible in plat_pub_versioned.cil (etc.); we just have to make
       sure we don't double-declare across files.

       If `all_cil_paths` is provided, every file in it is pre-scanned for
       existing `sepinject_aux_*` typeattribute declarations.  Those names
       are added to `aux_emitted` up front, so build_rewrite-generated
       redeclarations are suppressed.  This prevents the duplicate
       typeattribute error that bricks the build when (a) a prior run of
       this script already wrote aux decls into the CIL, or (b) the legacy
       `fix_neverallow_rewrites.py` helper wrote them.  secilc treats
       duplicate typeattribute declarations as fatal.

       `attr_map` and `all_types` are the global resolution context
       built by find_neverallow_conflicts and threaded through here so
       build_rewrite can perform robust vacuity checks (Bug 1).  When
       omitted, build_rewrite falls back to less precise string-name
       checks; this is acceptable for preview but the live rewriter
       should always pass them.

       Returns a dict mapping cil_path -> True/False (whether changes were made).
    """
    # Group by file
    by_file: dict = {}
    for c in conflicts:
        by_file.setdefault(c.neverallow.cil_path, []).append(c)

    # Cross-file registry of auxiliary attribute declarations.
    # Key: aux attribute name.
    # Value: (typeattribute_line, typeattributeset_line)
    # We accumulate as we rewrite, then emit each unique decl exactly once.
    aux_registry: dict = {}
    aux_emitted: set = set()  # aux names already written into some file

    # Bug 2 instrumentation: track which (target, class, perms) fingerprints
    # share an aux attribute.  An aux is correctly shared when two
    # rewrites have the same (src_expr, excluded_srcs) pair — e.g. two
    # neverallows on `init` for different perms.  But a reviewer should
    # see the blast radius, because a malformed aux silently breaks
    # every neverallow that uses it (see Bug 1 for what "broken" looks
    # like in practice).  We surface a warning when one name spans more
    # than one fingerprint.
    aux_fingerprints: dict = {}

    # Pre-populate aux_emitted from any pre-existing sepinject_aux_*
    # declarations.  Scan the union of (a) explicit all_cil_paths and
    # (b) files that have conflicts in this run.  Either input may contain
    # decls from a prior sepinject run or from the legacy
    # fix_neverallow_rewrites.py helper.
    scan_set: set = set()
    if all_cil_paths:
        for entry in all_cil_paths:
            # entries may be plain Paths or (tag, Path) tuples
            p = entry[1] if isinstance(entry, tuple) else entry
            scan_set.add(p)
    scan_set.update(by_file.keys())

    aux_decl_re = re.compile(
        r'^\s*\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)',
        re.MULTILINE,
    )
    for p in scan_set:
        try:
            existing_text = p.read_text(errors='replace')
        except OSError:
            continue
        for m in aux_decl_re.finditer(existing_text):
            aux_emitted.add(m.group(1))
    if aux_emitted:
        print(f"  [i] Found {len(aux_emitted)} pre-existing sepinject_aux_* "
              f"decl(s); will not re-emit.")

    # ---- Vacuity pre-pass for extend conflicts ----
    # Decisions are made up-front (with possible interactive prompts) so
    # the per-file rewrite loop below can simply consult the result.
    # Mapping: id(NeverallowConflict) -> decision string
    #   'extend'   -> proceed with extend (may be vacuous; ALL CAPS marker written)
    #   'permdrop' -> revert the existing aux rewrite, drop matched perms
    #   'skip'     -> leave existing aux unchanged, ALL CAPS marker written, no new exemption
    #   None / absent -> normal (non-vacuous) extend or fresh path
    vacuity_decisions: dict = {}
    # Group previously_rewritten conflicts by (file, line_no) so multiple
    # rules hitting the same line are decided once.
    extend_group_keys: dict = {}  # (cil_path, line_no) -> list[conflict]
    for c in conflicts:
        if c.neverallow.previously_rewritten:
            key = (c.neverallow.cil_path, c.neverallow.line_no)
            extend_group_keys.setdefault(key, []).append(c)

    for (cil_path_k, line_no_k), group in extend_group_keys.items():
        na = group[0].neverallow
        new_excluded = sorted({c.rule.src for c in group if c.rule.src})
        merged_excluded = sorted(set(na.prior_excluded_srcs) | set(new_excluded))
        merged_matched = sorted({p for c in group for p in c.matched_perms})

        # Vacuity check against the ORIGINAL neverallow's resolved source
        # set.  src_resolved on the conflict was computed against
        # na.src_expr (the original, NOT the live aux name), so it
        # already reflects the original's membership.
        src_resolved = group[0].src_resolved
        vacuous = False
        if src_resolved is not None:
            if src_resolved.issubset(set(merged_excluded)):
                vacuous = True
        else:
            # Resolution unavailable — string-compare fallback as elsewhere.
            src_norm = na.src_expr.strip().lstrip('(').rstrip(')').strip()
            if len(merged_excluded) == 1 and src_norm == merged_excluded[0]:
                vacuous = True

        if vacuous:
            remaining_perms = [p for p in na.perms if p not in merged_matched]
            decision = _prompt_vacuity_decision(
                na, new_excluded, merged_excluded, remaining_perms)
            for c in group:
                vacuity_decisions[id(c)] = decision

    # ---- Identify aux names that will be DEPRECATED by an extend ----
    # Each extend produces a NEW aux name (because the excluded set
    # differs), which leaves the previous aux name orphaned.  We comment
    # out its typeattribute / typeattributeset decls for audit clarity.
    # Only aux names whose extend decision is 'extend' or absent (i.e.
    # the extend actually goes through) get marked deprecated; 'skip'
    # and 'permdrop' decisions leave the existing aux in place.
    deprecated_auxes: set = set()
    for (_, _), group in extend_group_keys.items():
        decision = vacuity_decisions.get(id(group[0]), 'extend')
        if decision in ('extend',) or decision not in ('skip', 'permdrop'):
            # 'extend' (vacuous case proceeding) OR normal non-vacuous extend
            na = group[0].neverallow
            if na.aux_name:
                deprecated_auxes.add(na.aux_name)
        elif decision == 'permdrop':
            # The existing aux line is reverted to perm-drop, so the aux
            # is also orphaned.
            na = group[0].neverallow
            if na.aux_name:
                deprecated_auxes.add(na.aux_name)
        # 'skip' leaves the aux decl alone.

    deprecated_aux_ta_re = re.compile(
        r'^(\s*)\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)(.*)$'
    )
    deprecated_aux_tas_re = re.compile(
        r'^(\s*)\(\s*typeattributeset\s+(sepinject_aux_[A-Za-z0-9_]+)\b(.*)$'
    )

    results = {}
    for cil_path, file_conflicts in by_file.items():
        print(f"\n[*] Rewriting neverallows in: {cil_path}")
        rollback.snapshot(cil_path)

        text = cil_path.read_text(errors='replace')
        lines = text.splitlines(keepends=True)

        # Build a map: line_no -> list of conflicts hitting that line.
        line_conflicts: dict = {}
        for c in file_conflicts:
            line_conflicts.setdefault(c.neverallow.line_no, []).append(c)

        new_lines = []
        modified = 0
        for idx, raw_line in enumerate(lines, start=1):
            # ---- Deprecate orphaned aux decls in pass-through lines ----
            # We do this even on lines that aren't conflict targets,
            # because the aux decls live elsewhere in the file (typically
            # at the bottom) from the neverallow that uses them.
            if idx not in line_conflicts:
                m_ta = deprecated_aux_ta_re.match(raw_line.rstrip('\r\n'))
                m_tas = deprecated_aux_tas_re.match(raw_line.rstrip('\r\n'))
                if m_ta and m_ta.group(2) in deprecated_auxes:
                    new_lines.append(_SEPINJECT_AUX_DEPRECATED_HEADER)
                    new_lines.append(';; ' + raw_line)
                    modified += 1
                    continue
                if m_tas and m_tas.group(2) in deprecated_auxes:
                    new_lines.append(_SEPINJECT_AUX_DEPRECATED_HEADER)
                    new_lines.append(';; ' + raw_line)
                    modified += 1
                    continue
                new_lines.append(raw_line)
                continue

            cs = line_conflicts[idx]
            stripped_nl = raw_line.rstrip('\r\n')
            line_ending = raw_line[len(stripped_nl):]

            # Are all conflicts on this line for a previously-rewritten
            # neverallow?  (find_neverallow_conflicts emits at most one
            # CilNeverallow per (file, line_no), so they share the same
            # `previously_rewritten` flag — but we check defensively.)
            base_na = cs[0].neverallow
            is_extend = base_na.previously_rewritten

            # ---- Handle vacuity decisions for extend conflicts ----
            decision = vacuity_decisions.get(id(cs[0])) if is_extend else None
            if decision == 'skip':
                # Leave the existing live aux neverallow line UNCHANGED,
                # but prepend the ALL CAPS vacuity banner so the situation
                # is highly visible during audit.
                new_lines.append(_SEPINJECT_VACUITY_BANNER)
                new_lines.append(
                    f";; sepinject: SKIPPED extend for {{ "
                    f"{', '.join(sorted({c.rule.src for c in cs if c.rule.src}))}"
                    f" }} — would have produced empty carve-out\n"
                )
                new_lines.append(raw_line)
                # No modification counted — we deliberately left it alone.
                continue

            # Merge multiple conflicts on the same line.  We union the
            # matched perms (so the perm-drop fallback removes all of
            # them at once) and union the rule sources (so the carve-out
            # exempts every triggering allow rule in one expression
            # rather than building N separate auxes).  This keeps the
            # rewrite minimal and the protection as broad as possible:
            # only the specific domains being added are exempted.
            merged_matched = set()
            structural_any = False
            triggering_rules = []
            excluded_srcs_set: set = set()
            for c in cs:
                merged_matched.update(c.matched_perms)
                structural_any = structural_any or c.structural
                triggering_rules.append(c.rule)
                if c.rule.src:
                    excluded_srcs_set.add(c.rule.src)

            if is_extend:
                # ---- Extend path: comment out the live aux line, merge
                # prior + new exclusions, emit fresh aux + neverallow ----
                # The user requested this be commented-out-and-duplicated
                # rather than mutated in place, so the diff history is
                # fully auditable.  See the EXTEND PATH note in the
                # function docstring.
                new_lines.append(_SEPINJECT_EXTEND_HEADER)
                new_lines.append(
                    f";; sepinject: prior aux: {base_na.aux_name}\n"
                )
                new_lines.append(
                    f";; sepinject: prior exclusions: "
                    f"{{ {', '.join(base_na.prior_excluded_srcs)} }}\n"
                )
                new_lines.append(
                    f";; sepinject: now adding: "
                    f"{{ {', '.join(sorted(excluded_srcs_set))} }}\n"
                )
                new_lines.append(f";; {stripped_nl}{line_ending}")

                # If the user chose perm-drop for this vacuity case,
                # revert the aux rewrite and apply perm-drop to the
                # ORIGINAL neverallow instead.
                if decision == 'permdrop':
                    new_lines.append(_SEPINJECT_VACUITY_BANNER)
                    new_lines.append(
                        ";; sepinject: vacuity decision: perm-drop "
                        "fallback (existing aux rewrite reverted)\n"
                    )
                    remaining_perms = [p for p in base_na.perms
                                       if p not in merged_matched]
                    if remaining_perms:
                        pd_line = (
                            f"(neverallow {base_na.src_expr} {base_na.tgt_expr} "
                            f"({base_na.cls} {_format_perms(remaining_perms)}))"
                        )
                    else:
                        pd_line = (
                            ";; sepinject: refusal — no perms remain after drop; "
                            "neverallow protection is gone for this (src,tgt,cls)"
                        )
                    trigger_summary = ', '.join(
                        f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
                        for r in triggering_rules
                    )
                    new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
                    new_lines.append(pd_line + line_ending)
                    modified += 1
                    continue

                # Normal extend (whether non-vacuous or 'extend anyway').
                # Build merged excluded set from prior + new.
                merged_excluded = sorted(
                    set(base_na.prior_excluded_srcs) | excluded_srcs_set
                )

                # Build the new aux + new neverallow line.
                # base_na.src_expr / tgt_expr / cls / perms reflect the
                # ORIGINAL neverallow (recovered by parse_cil_neverallows),
                # so build_rewrite's carve-out path will produce a fresh
                # aux name derived from (original_src, merged_excluded).
                merged_conflict = NeverallowConflict(
                    rule=cs[0].rule,
                    neverallow=base_na,
                    matched_perms=sorted(merged_matched),
                    structural=structural_any,
                    src_resolved=cs[0].src_resolved,
                )
                if decision == 'extend':
                    # Vacuous extend — write the ALL CAPS marker; the
                    # rewrite itself may still be the carve-out form,
                    # but the user has accepted that it'll be empty.
                    new_lines.append(_SEPINJECT_VACUITY_BANNER)
                rewrite = build_rewrite(
                    merged_conflict,
                    aux_registry=aux_registry,
                    attr_map=attr_map,
                    all_types=all_types,
                    excluded_srcs=merged_excluded,
                    aux_fingerprints=aux_fingerprints,
                )
                trigger_summary = ', '.join(
                    f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
                    for r in triggering_rules
                )
                new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
                new_lines.append(rewrite + line_ending)
                modified += 1
                continue

            # ---- Fresh path (no prior rewrite) — original behavior ----
            new_lines.append(f";; sepinject: commented (neverallow rewritten below)\n")
            new_lines.append(f";; {stripped_nl}{line_ending}")

            merged_conflict = NeverallowConflict(
                rule=cs[0].rule,
                neverallow=base_na,
                matched_perms=sorted(merged_matched),
                structural=structural_any,
                src_resolved=cs[0].src_resolved,
            )
            rewrite = build_rewrite(
                merged_conflict,
                aux_registry=aux_registry,
                attr_map=attr_map,
                all_types=all_types,
                excluded_srcs=sorted(excluded_srcs_set),
                aux_fingerprints=aux_fingerprints,
            )
            trigger_summary = ', '.join(
                f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
                for r in triggering_rules
            )
            new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
            new_lines.append(rewrite + line_ending)
            modified += 1

        # Emit any auxiliary attribute declarations that haven't been written
        # yet.  We append them at the bottom of this file.  Subsequent files
        # processed in this run will skip aux names already emitted here.
        new_aux = [(n, d) for n, d in aux_registry.items() if n not in aux_emitted]
        if new_aux and modified:
            new_lines.append('\n')
            new_lines.append(';\n')
            new_lines.append('; --- sepinject auxiliary attributes ---\n')
            new_lines.append('; Declared by build_rewrite() to provide a valid CIL form for\n')
            new_lines.append('; neverallows whose source set had to be relaxed.  The inline\n')
            new_lines.append(';   (neverallow (and X (not Y)) ...)\n')
            new_lines.append('; form is not valid CIL — secilc fails to build an AST for it.\n')
            new_lines.append(';\n')
            for aux_name, (ta_line, tas_line) in new_aux:
                new_lines.append(ta_line + '\n')
                new_lines.append(tas_line + '\n')
                aux_emitted.add(aux_name)

        if modified:
            cil_path.write_text(''.join(new_lines))
            print(f"  [+] Rewrote {modified} neverallow line(s) in {cil_path.name}")
            if new_aux:
                print(f"      emitted {len(new_aux)} new auxiliary attribute decl(s)")
            results[cil_path] = True
        else:
            results[cil_path] = False

    # ---- Second pass: deprecate aux decls in files that didn't have
    # conflicts but DO contain decls for a deprecated aux ----
    # This catches the (rare) case where the aux decl lives in a
    # different CIL file than its referencing neverallow.
    if deprecated_auxes and all_cil_paths:
        extra_paths = []
        for entry in all_cil_paths:
            p = entry[1] if isinstance(entry, tuple) else entry
            if p and p.exists() and p not in by_file:
                extra_paths.append(p)
        for p in extra_paths:
            existing = p.read_text(errors='replace')
            ex_lines = existing.splitlines(keepends=True)
            touched = False
            out: list = []
            for raw in ex_lines:
                s = raw.rstrip('\r\n')
                m_ta = deprecated_aux_ta_re.match(s)
                m_tas = deprecated_aux_tas_re.match(s)
                if m_ta and m_ta.group(2) in deprecated_auxes:
                    out.append(_SEPINJECT_AUX_DEPRECATED_HEADER)
                    out.append(';; ' + raw)
                    touched = True
                elif m_tas and m_tas.group(2) in deprecated_auxes:
                    out.append(_SEPINJECT_AUX_DEPRECATED_HEADER)
                    out.append(';; ' + raw)
                    touched = True
                else:
                    out.append(raw)
            if touched:
                rollback.snapshot(p)
                p.write_text(''.join(out))
                print(f"  [+] Deprecated cross-file aux decl(s) in {p.name}")
                results[p] = True

    # Bug 2 — surface aux attribute reuse across substantively different
    # rewrites.  Sharing is correct semantics-wise (same source/carve-out
    # pair, two neverallows with different (tgt, cls, perms)), but a
    # malformed aux would break ALL of them.  Print a single grouped
    # summary so the reviewer can see the blast radius.
    reused = {n: fps for n, fps in aux_fingerprints.items() if len(fps) > 1}
    if reused:
        print(f"\n[!] {len(reused)} sepinject_aux_* attribute(s) reused across "
              f"substantively different rewrites:")
        for aux_name in sorted(reused):
            fps = reused[aux_name]
            print(f"  - {aux_name} used by {len(fps)} rewrite(s):")
            for tgt, cls, perms in sorted(fps):
                print(f"      tgt={tgt}  class={cls}  perms={{ {' '.join(perms)} }}")
        print(f"  Sharing is correct, but a malformed aux would break "
              f"every neverallow that references it — review the "
              f"(typeattributeset ...) bodies above carefully.")

    return results


# ===========================================================================
# mlsconstrain conflict detection and CIL rewriting
# ===========================================================================
#
# This section mirrors the neverallow handling above, adapted for MLS
# constraints.  The two directives are fundamentally different, and the
# differences drive every design choice below:
#
#   * A `neverallow` is a COMPILE-TIME assertion.  It never persists into
#     the runtime binary, so relaxing it means narrowing its SOURCE set
#     (carve-out) so `secilc` stops rejecting the paired `allow`.
#
#   * An `mlsconstrain` is a RUNTIME constraint.  The kernel evaluates its
#     boolean expression on every access to the constrained class/perms and
#     DENIES the access unless the expression is true.  Relaxing it means
#     WIDENING its expression so it evaluates true for the subject we want
#     to permit.  We do that by OR-ing in an exemption clause:
#
#         (mlsconstrain (CLS (PERMS)) ORIG_EXPR)
#       becomes
#         (mlsconstrain (CLS (PERMS)) (or ORIG_EXPR (eq t1 AUX)))
#
#     where AUX is a `sepinject_mlsaux_*` typeattribute whose membership is
#     the set of subject domains being exempted.  `(eq t1 ATTR)` is true iff
#     the source type is a member of ATTR — exactly how the stock policy's
#     own `(eq t1 mlstrustedsubject)` clauses work — so this is idiomatic and
#     compiles cleanly.  The exemption is subject-scoped, mirroring the
#     neverallow carve-out which narrows by source domain.
#
# Because widening is always well-defined, the mlsconstrain rewriter has NO
# vacuity / perm-drop / refusal fallbacks (the neverallow rewriter needs
# those only because narrowing a source set can empty it).  It also does not
# deprecate superseded aux decls: an `mlsaux` attribute is a plain union that
# may be shared by several constraints, and an unreferenced typeattribute is
# legal CIL, so leaving old ones in place is safe.
#
# Conflict detection cannot be exact — the constraint expression depends on
# runtime MLS levels (l1/l2/h1/h2) that are unknowable statically.  We use
# three-valued (Kleene) logic: type clauses (t1/t2 vs a type or attribute)
# are evaluated concretely against the proposed allow's (src, tgt); level,
# role, and user clauses evaluate to UNKNOWN.  A constraint is reported as a
# conflict unless it evaluates to definite TRUE — i.e. unless the type
# clauses ALONE already guarantee the access.  This is conservative in the
# same spirit as the neverallow scanner ("if we can't resolve, assume it
# might match").

@dataclass
class CilMlsconstrain:
    """A single (mlsconstrain (CLS (PERMS)) EXPR) statement parsed from a CIL
       file.

       When this constraint was already rewritten by a prior sepinject run,
       `previously_rewritten` is True and `expr_text` holds the ORIGINAL
       (pre-rewrite) boolean expression, recovered by stripping the trailing
       `(eq t1 sepinject_mlsaux_*)` exemption disjunct off the live line's
       outer `(or ORIG EXEMPT)`.  That lets the conflict detector recognize
       a fresh allow for a DIFFERENT domain as touching the SAME original
       constraint, so we extend the existing exemption instead of nesting a
       second `(or (or ORIG ...) ...)` wrapper.
    """
    cil_path: Path
    line_no: int            # 1-based line to comment out.  For a rewritten
                            # constraint this is the LIVE `(mlsconstrain ...
                            # (eq t1 sepinject_mlsaux_*))` line.
    raw_line: str           # exact text of the line to comment out (incl. any
                            # trailing newline).
    cls: str                # class name (e.g. "file")
    perms: list             # permission names (e.g. ["write","setattr"])
    expr_text: str          # raw S-expression text of the ORIGINAL constraint
                            # boolean (e.g. "(or (eq t2 app_data_file_type)
                            # (eq t1 mlstrustedsubject))").

    # ---- Sepinject-block metadata (set only when previously_rewritten) ----
    previously_rewritten: bool = False
    aux_name: Optional[str] = None            # existing sepinject_mlsaux_* name
    prior_exempted_srcs: list = field(default_factory=list)  # domains already exempted
    triggers_text: Optional[str] = None       # accumulated `;; sepinject: triggered by:` text
    original_line_no: Optional[int] = None    # line of the `;; (mlsconstrain ORIG ...)` comment


@dataclass
class MlsconstrainConflict:
    """A detected conflict between a proposed allow rule and an mlsconstrain
       that would (or could) deny it at runtime."""
    rule: 'TeRule'                   # the proposed allow rule
    mlsconstrain: CilMlsconstrain    # the constraint that blocks it
    matched_perms: list              # rule.perms covered by the constraint's perm set
    verdict: str                     # 'blocked' (Kleene FALSE — denied for all levels)
                                     # or 'maybe' (Kleene UNKNOWN — denied for some levels)


# ----- mlsconstrain sepinject-block markers (mirror the neverallow set) -----

_SEPINJECT_MLS_HEADER_RE = re.compile(
    r'^\s*;;\s*sepinject:\s*commented\s*\(mlsconstrain rewritten below\)',
)
_SEPINJECT_MLS_ORIG_RE = re.compile(
    r'^\s*;;\s*(\(mlsconstrain\b.*\))\s*$',
)
# A live, rewritten constraint line: its expression ends with an
# `(eq t1 sepinject_mlsaux_<name>)` exemption disjunct.
_SEPINJECT_MLS_LIVE_RE = re.compile(
    r'\(\s*eq\s+t1\s+(sepinject_mlsaux_[A-Za-z0-9_]+)\s*\)'
)

_SEPINJECT_MLS_COMMENTED_HDR = ";; sepinject: commented (mlsconstrain rewritten below)\n"
_SEPINJECT_MLS_EXTEND_HEADER  = ";; sepinject: mls superseded (extended exemption below)\n"


# ----- CIL extraction -----

def _split_mls_classperms(node):
    """Given the classperms node of an mlsconstrain — e.g. ['file',
       ['write','setattr']] or ['file','entrypoint'] — return (cls, perms)
       or (None, None) if the shape is unexpected (multi-class forms etc.)."""
    if not (isinstance(node, list) and len(node) == 2):
        return (None, None)
    cls_name, perms_node = node[0], node[1]
    if not isinstance(cls_name, str):
        return (None, None)
    if isinstance(perms_node, str):
        perms = [perms_node]
    elif isinstance(perms_node, list) and all(isinstance(p, str) for p in perms_node):
        perms = list(perms_node)
    else:
        return (None, None)
    return (cls_name, perms)


def _strip_mls_exemption(expr_node):
    """Given a parsed constraint expression node that is the outer
       `(or ORIG (eq t1 sepinject_mlsaux_NAME))` of a rewritten mlsconstrain,
       return (orig_expr_node, aux_name).  If the node is not a
       sepinject-rewritten expression, return (expr_node, None).

       Handles the general shape `(or ORIG (eq t1 sepinject_mlsaux_*))` where
       ORIG is any expression.  The exemption disjunct is always the LAST
       operand of the outer `or` (that's how build_mls_rewrite emits it)."""
    if not (isinstance(expr_node, list) and len(expr_node) >= 3
            and expr_node[0] == 'or'):
        return (expr_node, None)
    last = expr_node[-1]
    # last should be (eq t1 sepinject_mlsaux_NAME)
    if (isinstance(last, list) and len(last) == 3 and last[0] == 'eq'
            and last[1] == 't1' and isinstance(last[2], str)
            and last[2].startswith('sepinject_mlsaux_')):
        aux_name = last[2]
        rest = expr_node[1:-1]
        orig = rest[0] if len(rest) == 1 else (['or'] + rest)
        return (orig, aux_name)
    return (expr_node, None)


def parse_cil_mlsconstrains(cil_path: Path) -> list:
    """Walk a CIL file line-by-line and extract every top-level
       (mlsconstrain (CLS (PERMS)) EXPR) statement.

       As with parse_cil_neverallows, AOSP-generated CILs keep each
       mlsconstrain on a single line; multi-line forms are skipped with a
       warning.  Commented lines (`;`-prefixed) are ignored, so the
       `;; (mlsconstrain ...)` audit comment written by a prior rewrite is
       never re-parsed as live.

       A previously-rewritten constraint's live line ends with an
       `(eq t1 sepinject_mlsaux_*)` disjunct; we recover the ORIGINAL
       expression by stripping that disjunct and flag the record
       previously_rewritten=True so the rewriter extends the existing
       exemption rather than nesting a new one.
    """
    if not cil_path.exists():
        return []

    results = []
    skipped = 0
    text = cil_path.read_text(errors='replace')
    lines = text.splitlines(keepends=True)

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.lstrip()
        if not stripped or stripped.startswith(';'):
            continue
        if not (stripped.startswith('(mlsconstrain ')
                or stripped.startswith('(mlsconstrain\t')):
            continue
        if raw_line.count('(') != raw_line.count(')'):
            skipped += 1
            continue
        sexpr = _na_parse_sexpr_one(raw_line)
        if not (isinstance(sexpr, list) and len(sexpr) == 3
                and sexpr[0] == 'mlsconstrain'):
            skipped += 1
            continue
        cls_name, perms = _split_mls_classperms(sexpr[1])
        if cls_name is None:
            skipped += 1
            continue
        expr_node = sexpr[2]

        # Detect a previously-rewritten line and recover the original expr.
        prev = False
        aux_name = None
        if _SEPINJECT_MLS_LIVE_RE.search(raw_line):
            orig_node, aux_name = _strip_mls_exemption(expr_node)
            if aux_name is not None:
                prev = True
                expr_node = orig_node

        # Gather any immediately-preceding `;; sepinject: triggered by:`
        # audit lines and the `;; (mlsconstrain ORIG ...)` baseline comment
        # for lineage (best-effort; recovery does not depend on them).
        triggers_text = None
        original_line_no = None
        if prev:
            trig_bits = []
            j = idx - 2  # 0-based index of the line above
            while j >= 0 and lines[j].lstrip().startswith(';;'):
                m_t = _SEPINJECT_TRIGGERED_BY_RE.match(lines[j])
                if m_t:
                    trig_bits.append(m_t.group(1).rstrip())
                m_o = _SEPINJECT_MLS_ORIG_RE.match(lines[j])
                if m_o and 'sepinject_mlsaux_' not in m_o.group(1):
                    original_line_no = j + 1
                j -= 1
            if trig_bits:
                triggers_text = '; '.join(reversed(trig_bits))

        results.append(CilMlsconstrain(
            cil_path=cil_path,
            line_no=idx,
            raw_line=raw_line,
            cls=cls_name,
            perms=perms,
            expr_text=_na_sexpr_to_str(expr_node),
            previously_rewritten=prev,
            aux_name=aux_name,
            triggers_text=triggers_text,
            original_line_no=original_line_no,
        ))

    if skipped:
        print(f"  [~] {skipped} mlsconstrain line(s) in {cil_path.name} "
              f"skipped (multi-line, multi-class, or malformed)")
    return results


# ----- Three-valued (Kleene) constraint evaluation -----

_MLS_LEVEL_KW    = {'l1', 'l2', 'h1', 'h2'}
_MLS_ROLEUSER_KW = {'r1', 'r2', 'u1', 'u2'}
_MLS_TYPE_KW     = {'t1', 't2'}
_MLS_REL_OPS     = {'eq', 'neq', 'dom', 'domby', 'incomp', 'dominates'}

_KLEENE_NOT = {'T': 'F', 'F': 'T', 'U': 'U'}


def _mls_member(concrete_type: str, name: str,
                attr_map: dict, all_types: set) -> str:
    """Three-valued membership test: is `concrete_type` in the type set
       denoted by `name` (a type or attribute)?  'T'/'F'/'U'."""
    if name == concrete_type:
        return 'T'
    parsed = _na_parse_sexpr_one(name) if name.lstrip().startswith('(') else name
    s = _na_resolve_set(parsed, attr_map, all_types)
    if s is None:
        return 'U'
    return 'T' if concrete_type in s else 'F'


def _mls_eval_leaf(op: str, a, b, subj: str, tgt: str,
                   attr_map: dict, all_types: set) -> str:
    """Evaluate a single relational constraint leaf to 'T'/'F'/'U' given
       t1=subj, t2=tgt.  Only type-vs-type and type-vs-name comparisons are
       decidable; anything touching a level/role/user operand is 'U'."""
    if not (isinstance(a, str) and isinstance(b, str)):
        return 'U'

    # dom/domby/incomp/dominates are MLS-level relations — always runtime.
    if op not in ('eq', 'neq'):
        return 'U'

    a_is_t = a in _MLS_TYPE_KW
    b_is_t = b in _MLS_TYPE_KW
    a_is_runtime = a in _MLS_LEVEL_KW or a in _MLS_ROLEUSER_KW
    b_is_runtime = b in _MLS_LEVEL_KW or b in _MLS_ROLEUSER_KW

    def concrete(kw):
        return subj if kw == 't1' else tgt

    if a_is_t and b_is_t:
        # (eq t1 t2) — both known statically.
        res = 'T' if concrete(a) == concrete(b) else 'F'
    elif a_is_t and not (b_is_t or b_is_runtime):
        # (eq t1 NAME) / (eq t2 NAME)
        res = _mls_member(concrete(a), b, attr_map, all_types)
    elif b_is_t and not (a_is_t or a_is_runtime):
        res = _mls_member(concrete(b), a, attr_map, all_types)
    else:
        # Involves a level/role/user operand — runtime-dependent.
        return 'U'

    return _KLEENE_NOT[res] if op == 'neq' else res


def _mls_eval(expr, subj: str, tgt: str,
              attr_map: dict, all_types: set) -> str:
    """Kleene-evaluate a constraint expression to 'T'/'F'/'U'.

       T = the constraint is satisfied for (t1=subj, t2=tgt) regardless of
           runtime levels (type clauses alone force it true).
       F = the constraint is unsatisfied for all runtime levels (denied).
       U = satisfaction depends on runtime levels (may be denied)."""
    if isinstance(expr, str):
        # A bare atom is not a valid top-level constraint expr; be safe.
        return 'U'
    if not isinstance(expr, list) or not expr:
        return 'U'

    op = expr[0]
    if op == 'and':
        vals = [_mls_eval(a, subj, tgt, attr_map, all_types) for a in expr[1:]]
        if 'F' in vals:
            return 'F'
        if 'U' in vals:
            return 'U'
        return 'T'
    if op == 'or':
        vals = [_mls_eval(a, subj, tgt, attr_map, all_types) for a in expr[1:]]
        if 'T' in vals:
            return 'T'
        if 'U' in vals:
            return 'U'
        return 'F'
    if op == 'not':
        if len(expr) != 2:
            return 'U'
        return _KLEENE_NOT[_mls_eval(expr[1], subj, tgt, attr_map, all_types)]
    if op in _MLS_REL_OPS and len(expr) == 3:
        return _mls_eval_leaf(op, expr[1], expr[2], subj, tgt, attr_map, all_types)
    # Unknown / unexpected shape — conservative.
    return 'U'


# ----- Conflict detection -----

def find_mlsconstrain_conflicts(rules: list, cil_paths: list) -> tuple:
    """For each `allow` rule, scan all mlsconstrains across the given CIL
       files and return (conflicts, attr_map, all_types).

       A conflict is reported when ALL of:
         - rule.cls == mlsconstrain.cls
         - any p in rule.perms is in mlsconstrain.perms
         - the constraint does NOT evaluate to definite TRUE for
           (t1=rule.src, t2=rule.tgt) — i.e. the type clauses alone do not
           already guarantee the access (Kleene result is 'F' or 'U').

       Mirrors find_neverallow_conflicts: a merged global attr_map/all_types
       is built across every scanned file and augmented with the rules being
       added, so newly-declared domains resolve correctly.  prior_exempted_srcs
       is populated on previously-rewritten constraints so re-runs with the
       same input don't produce phantom "extend" rewrites.
    """
    conflicts = []

    # ---- global attr_map / all_types (same construction as neverallow) ----
    global_attr_map: dict = {}
    global_all_types: set = set()
    for _, cil_path in cil_paths:
        if not cil_path or not cil_path.exists():
            continue
        local_map = parse_cil_typeattributesets(cil_path)
        local_types = collect_all_type_names(cil_path)
        global_all_types.update(local_types)
        for attr_name, expr in local_map.items():
            if attr_name not in global_attr_map:
                global_attr_map[attr_name] = expr
            else:
                global_attr_map[attr_name] = ['or', global_attr_map[attr_name], expr]

    global_attr_map, global_all_types = _augment_attrmap_and_types_with_rules(
        rules, global_attr_map, global_all_types)

    def _resolve_prior_exemptions(mc: 'CilMlsconstrain') -> list:
        if not mc.previously_rewritten or not mc.aux_name:
            return []
        expr = global_attr_map.get(mc.aux_name)
        if expr is None:
            return []
        s = _na_resolve_set(expr, global_attr_map, global_all_types)
        return sorted(s) if s else []

    for label, cil_path in cil_paths:
        if not cil_path or not cil_path.exists():
            continue
        print(f"  [*] Scanning {label}: {cil_path.name}")
        mlscons = parse_cil_mlsconstrains(cil_path)
        if not mlscons:
            print(f"      no mlsconstrains parsed")
            continue
        print(f"      {len(mlscons)} mlsconstrain(s) found")

        for mc in mlscons:
            if mc.previously_rewritten and not mc.prior_exempted_srcs:
                mc.prior_exempted_srcs = _resolve_prior_exemptions(mc)

        attr_map = global_attr_map
        all_types = global_all_types
        expr_cache: dict = {}

        for rule in rules:
            if rule.op != 'allow' or not rule.cls or not rule.perms:
                continue
            for mc in mlscons:
                if mc.cls != rule.cls:
                    continue
                matched = [p for p in rule.perms if p in mc.perms]
                if not matched:
                    continue
                # Already exempted by an existing carve-out → nothing to do.
                if mc.previously_rewritten and rule.src in mc.prior_exempted_srcs:
                    continue

                tgt = rule.src if rule.tgt == 'self' else rule.tgt
                key = (id(mc), rule.src, tgt)
                if key in expr_cache:
                    verdict3 = expr_cache[key]
                else:
                    parsed = _na_parse_sexpr_one(mc.expr_text) \
                        if mc.expr_text.lstrip().startswith('(') else mc.expr_text
                    verdict3 = _mls_eval(parsed, rule.src, tgt, attr_map, all_types)
                    expr_cache[key] = verdict3

                if verdict3 == 'T':
                    # Type clauses already guarantee the access — no conflict.
                    continue

                conflicts.append(MlsconstrainConflict(
                    rule=rule,
                    mlsconstrain=mc,
                    matched_perms=matched,
                    verdict='blocked' if verdict3 == 'F' else 'maybe',
                ))

    return conflicts, global_attr_map, global_all_types


# ----- Rewrite generation -----

def _make_mls_aux_attr_name(exempted_srcs) -> str:
    """Deterministic, readable name for the mlsconstrain-exemption auxiliary
       attribute.  Keyed ONLY on the exempted subject set (not on class or
       perms), so every constraint exempting the same set of domains shares a
       single attribute — minimizing declarations.  Stable across re-runs."""
    if isinstance(exempted_srcs, str):
        excl = [exempted_srcs]
    else:
        excl = sorted({s for s in exempted_srcs if s})
    excl_str = '_'.join(re.sub(r'\s+', '', s) for s in excl)
    h = hashlib.sha1(excl_str.encode()).hexdigest()[:6]
    safe = re.sub(r'[^A-Za-z0-9_]+', '_', excl_str)[:40]
    return f"sepinject_mlsaux_{safe}_{h}"


def build_mls_rewrite(conflict, aux_registry: dict = None,
                      exempted_srcs: Optional[list] = None) -> str:
    """Construct the rewritten mlsconstrain line: widen the original
       expression with an `(or ORIG (eq t1 AUX))` exemption disjunct, where
       AUX is a sepinject_mlsaux_* attribute whose membership is the exempted
       subject set.

       If `aux_registry` is provided, the aux's (typeattribute, typeattributeset)
       decl pair is recorded there so the caller emits it once.  Widening is
       always well-defined, so — unlike build_rewrite for neverallows — there
       is no vacuity/perm-drop/refusal path.
    """
    mc = conflict.mlsconstrain
    if exempted_srcs is None:
        exempted_srcs = [conflict.rule.src]
    excl = sorted({s for s in exempted_srcs if s})
    if not excl:
        # Degenerate: nothing to exempt.  Return the original unchanged so
        # the caller's commented-out line is effectively restored.
        return (f"(mlsconstrain ({mc.cls} {_format_perms(mc.perms)}) "
                f"{mc.expr_text})")

    aux_name = _make_mls_aux_attr_name(excl)
    if aux_registry is not None and aux_name not in aux_registry:
        members = '(' + ' '.join(excl) + ')'
        aux_registry[aux_name] = (
            f'(typeattribute {aux_name})',
            f'(typeattributeset {aux_name} {members})',
        )

    new_expr = f'(or {mc.expr_text} (eq t1 {aux_name}))'
    return (f"(mlsconstrain ({mc.cls} {_format_perms(mc.perms)}) {new_expr})")


# ----- Conflict prompt -----

def prompt_mlsconstrain_conflicts(conflicts: list) -> bool:
    """Display all detected mlsconstrain conflicts and ask to proceed.
       Default on empty input is NO.  Returns True iff the user typed y/yes."""
    print("\n" + "=" * 70)
    print(f"[!] {len(conflicts)} mlsconstrain conflict(s) detected in CIL source")
    print("=" * 70)

    for i, c in enumerate(conflicts, 1):
        rule = c.rule
        mc = c.mlsconstrain
        print(f"\n  Conflict {i}:")
        print(f"    Adding:    allow {rule.src} {rule.tgt}:{rule.cls} "
              f"{{ {' '.join(rule.perms)} }};")
        print(f"    Constraint:(mlsconstrain ({mc.cls} "
              f"{{ {' '.join(mc.perms)} }}) {mc.expr_text})")
        print(f"    Source:    {mc.cil_path}:{mc.line_no}")
        print(f"    Matched:   perm(s) {{ {' '.join(c.matched_perms)} }}")
        if c.verdict == 'blocked':
            print(f"    Verdict:   DENIED for all MLS levels "
                  f"(type clauses alone reject t1={rule.src})")
        else:
            print(f"    Verdict:   may be denied depending on runtime MLS "
                  f"levels (no type clause guarantees the access)")
        if mc.previously_rewritten:
            merged = sorted(set(mc.prior_exempted_srcs) | {rule.src})
            print(f"    State:     existing sepinject exemption in place")
            print(f"               aux={mc.aux_name}")
            print(f"               already exempted: "
                  f"{{ {', '.join(mc.prior_exempted_srcs)} }}")
            print(f"    Rewrite:   (will EXTEND exemption — merged set: "
                  f"{{ {', '.join(merged)} }})")
            preview = build_mls_rewrite(c, exempted_srcs=merged)
        else:
            print(f"    Rewrite:   (will exempt '{rule.src}' via "
                  f"(or ORIG (eq t1 sepinject_mlsaux_*)))")
            preview = build_mls_rewrite(c)
        print(f"    Proposed:  {preview}")

    print("\n" + "=" * 70)
    print("If you proceed:")
    print("  - Each conflicting mlsconstrain line is commented out in place")
    print("  - A widened version (with the exemption disjunct) is inserted below it")
    print("  - A sepinject_mlsaux_* attribute holding the exempted domain(s)")
    print("    is appended to the file, and SHA-256 sidecars are regenerated")
    print("  - This RELAXES an MLS runtime constraint — review each one")
    print("If you decline:")
    print("  - All files modified so far this run are reverted from snapshot")
    print("  - The tool exits without applying any changes")
    print("=" * 70)

    try:
        answer = input("\nProceed with mlsconstrain rewrites? [y/N]: ").strip().lower()
    except EOFError:
        answer = ''
    return answer in ('y', 'yes')


# ----- CIL file mutation -----

def apply_mlsconstrain_rewrites(conflicts: list, rollback: RollbackSession,
                                all_cil_paths: list | None = None,
                                attr_map: dict | None = None,
                                all_types: set | None = None) -> dict:
    """Group conflicts by CIL file and apply the mlsconstrain rewrites.

       Fresh path: the original constraint line is commented out with a
       `;; sepinject: commented (mlsconstrain rewritten below)` header, its
       original text preserved in a `;; (mlsconstrain ...)` audit comment,
       and a widened line inserted below.

       Extend path (previously_rewritten): the live rewritten line is
       commented out under a `;; sepinject: mls superseded (extended
       exemption below)` header with prior/now-adding audit lines, and a new
       widened line referencing an aux for the MERGED exemption set is
       written.

       Auxiliary `sepinject_mlsaux_*` decls are emitted once, at the bottom
       of the first file that introduces them; pre-existing decls (from a
       prior run) are pre-scanned and not re-emitted.  Superseded aux decls
       are NOT removed — an mlsaux union may be shared by other constraints,
       and an unreferenced typeattribute is legal CIL.

       Returns a dict mapping cil_path -> True/False (changes made).
    """
    by_file: dict = {}
    for c in conflicts:
        by_file.setdefault(c.mlsconstrain.cil_path, []).append(c)

    aux_registry: dict = {}
    aux_emitted: set = set()

    # Pre-scan every candidate file for existing sepinject_mlsaux_* decls so
    # we never double-declare (secilc treats that as fatal).
    scan_set: set = set()
    if all_cil_paths:
        for entry in all_cil_paths:
            p = entry[1] if isinstance(entry, tuple) else entry
            scan_set.add(p)
    scan_set.update(by_file.keys())

    mlsaux_decl_re = re.compile(
        r'^\s*\(\s*typeattribute\s+(sepinject_mlsaux_[A-Za-z0-9_]+)\s*\)',
        re.MULTILINE,
    )
    for p in scan_set:
        try:
            existing_text = p.read_text(errors='replace')
        except OSError:
            continue
        for m in mlsaux_decl_re.finditer(existing_text):
            aux_emitted.add(m.group(1))
    if aux_emitted:
        print(f"  [i] Found {len(aux_emitted)} pre-existing sepinject_mlsaux_* "
              f"decl(s); will not re-emit.")

    results = {}
    for cil_path, file_conflicts in by_file.items():
        print(f"\n[*] Rewriting mlsconstrains in: {cil_path}")
        rollback.snapshot(cil_path)

        text = cil_path.read_text(errors='replace')
        lines = text.splitlines(keepends=True)

        line_conflicts: dict = {}
        for c in file_conflicts:
            line_conflicts.setdefault(c.mlsconstrain.line_no, []).append(c)

        new_lines = []
        modified = 0
        for idx, raw_line in enumerate(lines, start=1):
            if idx not in line_conflicts:
                new_lines.append(raw_line)
                continue

            cs = line_conflicts[idx]
            stripped_nl = raw_line.rstrip('\r\n')
            line_ending = raw_line[len(stripped_nl):] or '\n'

            base_mc = cs[0].mlsconstrain
            is_extend = base_mc.previously_rewritten

            # Union the sources of every rule hitting this line so a single
            # widened constraint exempts them all.
            new_srcs = sorted({c.rule.src for c in cs if c.rule.src})
            triggering_rules = [c.rule for c in cs]
            trigger_summary = ', '.join(
                f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
                for r in triggering_rules
            )

            if is_extend:
                merged_excluded = sorted(set(base_mc.prior_exempted_srcs)
                                         | set(new_srcs))
                new_lines.append(_SEPINJECT_MLS_EXTEND_HEADER)
                new_lines.append(f";; sepinject: prior mlsaux: {base_mc.aux_name}\n")
                new_lines.append(
                    f";; sepinject: prior exemptions: "
                    f"{{ {', '.join(base_mc.prior_exempted_srcs)} }}\n")
                new_lines.append(
                    f";; sepinject: now adding: {{ {', '.join(new_srcs)} }}\n")
                new_lines.append(f";; {stripped_nl}{line_ending}")
                merged_conflict = MlsconstrainConflict(
                    rule=cs[0].rule, mlsconstrain=base_mc,
                    matched_perms=cs[0].matched_perms, verdict=cs[0].verdict,
                )
                rewrite = build_mls_rewrite(
                    merged_conflict, aux_registry=aux_registry,
                    exempted_srcs=merged_excluded)
            else:
                new_lines.append(_SEPINJECT_MLS_COMMENTED_HDR)
                new_lines.append(f";; {stripped_nl}{line_ending}")
                merged_conflict = MlsconstrainConflict(
                    rule=cs[0].rule, mlsconstrain=base_mc,
                    matched_perms=cs[0].matched_perms, verdict=cs[0].verdict,
                )
                rewrite = build_mls_rewrite(
                    merged_conflict, aux_registry=aux_registry,
                    exempted_srcs=new_srcs)

            new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
            new_lines.append(rewrite + line_ending)
            modified += 1

        # Emit new aux decls at the bottom of this file.
        new_aux = [(n, d) for n, d in aux_registry.items() if n not in aux_emitted]
        if new_aux and modified:
            new_lines.append('\n')
            new_lines.append(';\n')
            new_lines.append('; --- sepinject mlsconstrain-exemption auxiliary attributes ---\n')
            new_lines.append('; Declared by build_mls_rewrite() to hold the subject domains\n')
            new_lines.append('; exempted from an MLS constraint via (eq t1 <attr>).  An\n')
            new_lines.append('; unreferenced one is harmless; a shared one may back several\n')
            new_lines.append('; constraints.\n')
            new_lines.append(';\n')
            for aux_name, (ta_line, tas_line) in new_aux:
                new_lines.append(ta_line + '\n')
                new_lines.append(tas_line + '\n')
                aux_emitted.add(aux_name)

        if modified:
            cil_path.write_text(''.join(new_lines))
            print(f"  [+] Rewrote {modified} mlsconstrain line(s) in {cil_path.name}")
            if new_aux:
                print(f"      emitted {len(new_aux)} new mlsaux attribute decl(s)")
            results[cil_path] = True
        else:
            results[cil_path] = False

    return results


# ===========================================================================
# Policy validation / repair (--validate / --validate-full)
# ===========================================================================
#
# The validate workflow inspects existing CIL files for broken sepinject
# artifacts left behind by buggy earlier runs (e.g. the cascade bug fixed
# in Phase 1: `sepinject_aux_sepinject_aux_*` references that no compiler
# accepts) and offers to repair them.
#
# Two modes:
#
#   --validate         (default, "surgical")
#     Scan for measurable defects and offer to repair each.  Every
#     repair is anchored to the recovered `;; (neverallow ORIG ...)`
#     audit comment from the very first rewrite of that neverallow,
#     so the rebuild is from baseline regardless of how many cascade
#     levels accumulated above it.
#
#   --validate-full    ("total rebuild")
#     Treat every sepinject artifact in every targeted CIL file as
#     suspect.  Comment them all out and recreate clean exemptions for
#     each recovered original neverallow, using the union of every
#     `;; sepinject: triggered by:` line that points at it.  This is
#     the bigger hammer; surgical is preferred when feasible.
#
# Both modes back up every targeted CIL file to a timestamped subdir
# under <rom-root> before making any modification (skipped under
# --dry-run).
#
# Non-neverallow issues (file_contexts / property_contexts / service_contexts
# domain or context references that don't resolve) are out of scope for
# this iteration — see Q4 in the conversation.

# ----- Issue records -----

@dataclass
class ValidateIssue:
    """A single defect detected by scan_validate_issues().

       `category` is always 'neverallow' in this iteration; reserved for
       future expansion to non-neverallow checks.

       `kind` is a short machine-readable code (see _ISSUE_KINDS below).
       `cil_path` and `line_nos` identify where the issue lives.
       `description` is a one-line human-readable summary.
       `repairable` indicates whether scan + repair can fix the issue
       automatically (False means manual review only — e.g. an
       unrecoverable block where the original `;;` audit comment is
       missing).
       `block_info` (when applicable) carries the sepinject-block
       metadata produced by _find_sepinject_blocks; used by the
       repair pass.
    """
    category: str
    kind: str
    cil_path: Path
    line_nos: list
    description: str
    repairable: bool = True
    block_info: Optional[dict] = None
    aux_name: Optional[str] = None


_ISSUE_KINDS = {
    'nested_aux_ref':       'aux typeattributeset references another sepinject_aux_*',
    'dangling_aux_ref':     'live `(neverallow sepinject_aux_X ...)` with no typeattributeset',
    'orphaned_aux_decl':    'sepinject_aux_X declared but never referenced by any live neverallow',
    'empty_carveout':       'aux typeattributeset resolves to empty source set',
    'duplicate_aux_set':    'multiple typeattributeset lines for the same sepinject_aux_X',
    'unrecoverable_block':  'sepinject block missing the `;; (neverallow ORIG ...)` audit comment',
    'cascade_aux_name':     'aux name itself contains nested `sepinject_aux_sepinject_aux_*`',
}


# ----- Triggers-text parser -----

# Matches a single rule in a `;; sepinject: triggered by:` audit line.
# Example: `allow my_domain_one my_attr_target_type:file {write}`
# We accept either `{...}` or `(...)` for the perms list because the
# audit format has evolved slightly over versions.
_TRIGGER_RULE_RE = re.compile(
    r'allow\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+):([A-Za-z0-9_]+)\s+'
    r'[{(]\s*([A-Za-z0-9_\s]+?)\s*[})]',
)


def _parse_triggers_text(text: Optional[str]) -> list:
    """Parse a `;; sepinject: triggered by: ...` audit line into a list of
       TeRule objects.  Multiple rules are separated by commas.  Returns
       an empty list on parse failure.

       Example input:
         "allow d1 t:file {write}, allow d2 t:file {write read}"
       Example output:
         [TeRule(op='allow', src='d1', tgt='t', cls='file', perms=['write']),
          TeRule(op='allow', src='d2', tgt='t', cls='file', perms=['write','read'])]
    """
    if not text:
        return []
    out = []
    for m in _TRIGGER_RULE_RE.finditer(text):
        src, tgt, cls, perms_str = m.groups()
        perms = perms_str.split()
        out.append(TeRule(op='allow', src=src, tgt=tgt, cls=cls, perms=perms))
    return out


# ----- Issue scanner -----

def scan_validate_issues(cil_paths: list,
                         attr_map: Optional[dict] = None,
                         all_types: Optional[set] = None,
                         full_rebuild: bool = False) -> list:
    """Scan the given CIL files and return a list of ValidateIssue records.

       In surgical mode (full_rebuild=False), only flag measurable defects.
       In full mode (full_rebuild=True), additionally flag EVERY sepinject
       block as `cascade_aux_name` (a synthetic catch-all kind) so the
       repair pass treats every block as needing replacement, even if
       it's currently well-formed.  This is what makes --validate-full
       a "rebuild everything from baseline" operation.

       `attr_map` and `all_types` are optional resolution context for
       empty-carveout checks.  When omitted those checks are skipped.

       Each entry in `cil_paths` may be either a Path or a (label, Path)
       tuple, matching the convention used by find_neverallow_conflicts.
    """
    issues: list = []

    # Normalize cil_paths to (label, Path) form.
    norm_paths = []
    for entry in cil_paths:
        if isinstance(entry, tuple):
            norm_paths.append(entry)
        else:
            norm_paths.append((entry.name, entry))

    # ---- First sweep: gather global state across files ----
    # We need cross-file visibility because aux decls and their
    # referencing neverallows can live in different files.
    all_aux_decls: dict = {}     # aux_name -> list of (cil_path, line_no, raw_line)
    all_aux_sets: dict = {}      # aux_name -> list of (cil_path, line_no, raw_line, body_node)
    all_live_aux_refs: dict = {} # aux_name -> list of (cil_path, line_no, raw_line)
    all_blocks_by_file: dict = {}  # cil_path -> dict (live_line_no -> block_info)

    aux_ta_re = re.compile(
        r'^\s*\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)',
    )
    aux_tas_re = re.compile(
        r'^\s*\(\s*typeattributeset\s+(sepinject_aux_[A-Za-z0-9_]+)\b',
    )

    for label, cil_path in norm_paths:
        if not cil_path or not cil_path.exists():
            continue
        text = cil_path.read_text(errors='replace')
        lines = text.splitlines(keepends=True)

        # Detect sepinject blocks.
        blocks = _find_sepinject_blocks(lines)
        all_blocks_by_file[cil_path] = blocks

        # Aux references in LIVE (uncommented) neverallow lines.
        # Walk each live aux-based neverallow line in any sepinject block.
        for live_ln, info in blocks.items():
            aux = info['aux_name']
            raw = lines[live_ln - 1]
            all_live_aux_refs.setdefault(aux, []).append((cil_path, live_ln, raw))

        # Walk every line for aux declarations / sets, but only count
        # the LIVE (non-commented) ones — `;;` and `;` commented decls
        # are inert.
        for idx, raw in enumerate(lines, start=1):
            s = raw.lstrip()
            if not s or s.startswith(';'):
                continue
            m_ta = aux_ta_re.match(raw)
            if m_ta:
                all_aux_decls.setdefault(m_ta.group(1), []).append(
                    (cil_path, idx, raw))
                continue
            m_tas = aux_tas_re.match(raw)
            if m_tas:
                # Parse the body to extract (and X (not Y)) shape.
                aux_name = m_tas.group(1)
                sexpr = _na_parse_sexpr_one(raw)
                body_node = None
                if (isinstance(sexpr, list) and len(sexpr) >= 3
                        and sexpr[0] == 'typeattributeset'):
                    body_node = sexpr[2]
                all_aux_sets.setdefault(aux_name, []).append(
                    (cil_path, idx, raw, body_node))

    # ---- Per-file issue scan ----
    for label, cil_path in norm_paths:
        if not cil_path or not cil_path.exists():
            continue
        blocks = all_blocks_by_file.get(cil_path, {})

        # E. Unrecoverable blocks — no `;; (neverallow ORIG ...)` audit comment
        for live_ln, info in blocks.items():
            if info.get('original_text') is None:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='unrecoverable_block',
                    cil_path=cil_path,
                    line_nos=sorted(info['block_line_nos']),
                    description=(
                        f"sepinject block at line {live_ln} has no "
                        f"`;; (neverallow ORIG ...)` audit comment — "
                        f"original cannot be recovered, manual review required"
                    ),
                    repairable=False,
                    block_info={'cil_path': cil_path, **info, 'live_line_no': live_ln},
                ))

        # F. Cascade in aux name — aux_name contains nested `sepinject_aux_sepinject_aux_`
        for live_ln, info in blocks.items():
            aux = info['aux_name'] or ''
            if 'sepinject_aux_sepinject_aux_' in aux:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='cascade_aux_name',
                    cil_path=cil_path,
                    line_nos=sorted(info['block_line_nos']),
                    description=(
                        f"sepinject block at line {live_ln} references "
                        f"cascaded aux name `{aux}` — symptom of the "
                        f"pre-fix cascade bug; will rebuild from baseline"
                    ),
                    repairable=info.get('original_text') is not None,
                    block_info={'cil_path': cil_path, **info, 'live_line_no': live_ln},
                    aux_name=aux,
                ))

        # When --validate-full is requested, flag every non-empty block
        # (even well-formed ones) so the repair pass treats them all.
        # We tag these with the same `cascade_aux_name` repair-handler
        # path because the rebuild semantics are identical: extract
        # original + triggers, replace with a clean from-baseline rewrite.
        if full_rebuild:
            for live_ln, info in blocks.items():
                # Skip if already covered by a more-specific issue above.
                already = any(
                    i.cil_path == cil_path
                    and live_ln in i.line_nos
                    and i.kind in ('cascade_aux_name', 'unrecoverable_block')
                    for i in issues
                )
                if already:
                    continue
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='cascade_aux_name',
                    cil_path=cil_path,
                    line_nos=sorted(info['block_line_nos']),
                    description=(
                        f"sepinject block at line {live_ln} flagged for "
                        f"full rebuild from baseline (--validate-full)"
                    ),
                    repairable=info.get('original_text') is not None,
                    block_info={'cil_path': cil_path, **info, 'live_line_no': live_ln},
                    aux_name=info['aux_name'],
                ))

    # ---- Cross-file checks ----

    # A. Nested aux ref — aux typeattributeset's inner expression
    # references another sepinject_aux_* attribute.
    def _node_refs_sepinject_aux(node) -> Optional[str]:
        if isinstance(node, str):
            if node.startswith('sepinject_aux_'):
                return node
            return None
        if isinstance(node, list):
            for c in node:
                hit = _node_refs_sepinject_aux(c)
                if hit:
                    return hit
        return None

    for aux_name, occurrences in all_aux_sets.items():
        for cil_path, line_no, raw, body in occurrences:
            if body is None:
                continue
            inner_text, excl = _parse_aux_typeattributeset(body)
            if inner_text is None:
                # body wasn't `(and INNER (not EXCL))` form — that's not
                # itself an issue (could be a degenerate aux that just
                # equals some set), but check for nested refs anywhere.
                nested = _node_refs_sepinject_aux(body)
            else:
                # Parse inner_text and see if it references a sepinject_aux_*
                inner_node = _na_parse_sexpr_one(inner_text) \
                    if inner_text.startswith('(') else inner_text
                nested = _node_refs_sepinject_aux(inner_node)
            if nested:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='nested_aux_ref',
                    cil_path=cil_path,
                    line_nos=[line_no],
                    description=(
                        f"typeattributeset for `{aux_name}` references "
                        f"another sepinject_aux attribute `{nested}` — "
                        f"this is the cascade bug; rebuild from baseline"
                    ),
                    aux_name=aux_name,
                ))

    # B. Dangling aux ref — live `(neverallow sepinject_aux_X ...)` with no typeattributeset
    for aux_name, refs in all_live_aux_refs.items():
        if aux_name not in all_aux_sets:
            for cil_path, line_no, raw in refs:
                # If we have a block_info for this reference, attach it
                # so the repair pass can find the original.
                bi = None
                blocks = all_blocks_by_file.get(cil_path, {})
                if line_no in blocks:
                    bi = {'cil_path': cil_path, **blocks[line_no],
                          'live_line_no': line_no}
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='dangling_aux_ref',
                    cil_path=cil_path,
                    line_nos=[line_no],
                    description=(
                        f"live `(neverallow {aux_name} ...)` at line "
                        f"{line_no} has no matching typeattributeset — "
                        f"the neverallow constrains nothing"
                    ),
                    block_info=bi,
                    aux_name=aux_name,
                    repairable=(bi is not None
                                and bi.get('original_text') is not None),
                ))

    # C. Orphaned aux decl — `(typeattribute sepinject_aux_X)` with no
    # live `(neverallow sepinject_aux_X ...)` referencing it AND no
    # typeattributeset.  Note: an aux with a typeattributeset but no
    # live neverallow ref is suspicious too (e.g. left over from a
    # previous extend operation), but it's benign — secilc tolerates it.
    # We flag it as repairable so --validate-full can clean it up.
    for aux_name, decls in all_aux_decls.items():
        has_live_ref = aux_name in all_live_aux_refs
        has_set = aux_name in all_aux_sets
        if not has_live_ref and not has_set:
            for cil_path, line_no, raw in decls:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='orphaned_aux_decl',
                    cil_path=cil_path,
                    line_nos=[line_no],
                    description=(
                        f"`(typeattribute {aux_name})` at line {line_no} "
                        f"is orphaned (no typeattributeset, no live "
                        f"neverallow reference)"
                    ),
                    aux_name=aux_name,
                    repairable=True,
                ))
        elif not has_live_ref and full_rebuild:
            # Aux has a set but no live neverallow — only flag under
            # --validate-full (it's benign but stale).
            for cil_path, line_no, raw in decls:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='orphaned_aux_decl',
                    cil_path=cil_path,
                    line_nos=[line_no],
                    description=(
                        f"`(typeattribute {aux_name})` at line {line_no} "
                        f"is stale (declared and set, but no live "
                        f"neverallow uses it — likely left over from a "
                        f"prior extend operation)"
                    ),
                    aux_name=aux_name,
                    repairable=True,
                ))

    # D. Empty carveout — typeattributeset resolves to empty source set
    if attr_map is not None and all_types is not None:
        for aux_name, occurrences in all_aux_sets.items():
            for cil_path, line_no, raw, body in occurrences:
                if body is None:
                    continue
                inner_text, excl = _parse_aux_typeattributeset(body)
                if inner_text is None or excl is None:
                    continue
                inner_node = _na_parse_sexpr_one(inner_text) \
                    if inner_text.startswith('(') else inner_text
                resolved = _na_resolve_set(inner_node, attr_map, all_types)
                if resolved is not None and resolved.issubset(set(excl)):
                    issues.append(ValidateIssue(
                        category='neverallow',
                        kind='empty_carveout',
                        cil_path=cil_path,
                        line_nos=[line_no],
                        description=(
                            f"`{aux_name}` typeattributeset is "
                            f"effectively empty (inner set "
                            f"{{ {', '.join(sorted(resolved))} }} ⊆ "
                            f"excluded {{ {', '.join(excl)} }}) — "
                            f"the neverallow constrains nothing"
                        ),
                        aux_name=aux_name,
                        repairable=True,
                    ))

    # E. Duplicate aux set — multiple typeattributeset lines for same aux
    for aux_name, occurrences in all_aux_sets.items():
        if len(occurrences) > 1:
            for cil_path, line_no, raw, body in occurrences:
                issues.append(ValidateIssue(
                    category='neverallow',
                    kind='duplicate_aux_set',
                    cil_path=cil_path,
                    line_nos=[line_no],
                    description=(
                        f"`{aux_name}` has {len(occurrences)} "
                        f"typeattributeset definitions — only one should "
                        f"exist; secilc unions them, so this still "
                        f"compiles but is a maintenance hazard"
                    ),
                    aux_name=aux_name,
                    repairable=True,
                ))

    return issues


# ----- Backup helper -----

def make_validate_backup(rom_root: Path, cil_paths: list) -> Path:
    """Copy every CIL file at `cil_paths` to a timestamped subdirectory
       under `rom_root` and return the backup directory path.

       Backup dir layout mirrors the source tree relative to rom_root,
       so a backed-up file at <rom_root>/system/.../plat_sepolicy.cil
       lives at <rom_root>/sepinject_validate_backup_<TS>/system/.../plat_sepolicy.cil.

       Raises OSError on backup failure (caller should abort).
    """
    ts = time.strftime('%Y%m%d_%H%M%S')
    backup_dir = rom_root / f'sepinject_validate_backup_{ts}'
    backup_dir.mkdir(parents=True, exist_ok=False)
    n = 0
    for entry in cil_paths:
        p = entry[1] if isinstance(entry, tuple) else entry
        if not p or not p.exists():
            continue
        try:
            rel = p.resolve().relative_to(rom_root.resolve())
        except ValueError:
            # File is outside rom_root — store under a synthetic 'external/' subdir.
            rel = Path('external') / p.name
        dest = backup_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        n += 1
    print(f"  [+] Backed up {n} file(s) to: {backup_dir}")
    return backup_dir


# ----- Repair driver -----

def _group_blocks_by_original(blocks_per_file: dict) -> dict:
    """Group sepinject blocks across all files by their recovered
       original neverallow text.  Returns a dict:
         (cil_path, original_text_norm) -> {
             'original_text': str,
             'cil_path': Path,
             'blocks':   list of block_info dicts,
             'triggers': list of TeRule objects (unioned across all blocks),
         }

       Grouping is per-file because secilc resolves attributes globally
       but neverallow lines themselves are per-file (we can't move a
       neverallow from plat to vendor).

       The original_text is normalized by stripping whitespace so minor
       formatting variations don't fragment the grouping.
    """
    groups: dict = {}
    for cil_path, blocks in blocks_per_file.items():
        for live_ln, info in blocks.items():
            orig = info.get('original_text')
            if not orig:
                continue
            key = (cil_path, ' '.join(orig.split()))  # normalized
            if key not in groups:
                groups[key] = {
                    'original_text': orig,
                    'cil_path':      cil_path,
                    'blocks':        [],
                    'triggers':      [],
                }
            groups[key]['blocks'].append({'live_line_no': live_ln, **info})
            groups[key]['triggers'].extend(_parse_triggers_text(info.get('triggers_text')))
    # De-dup triggers per group (same rule may appear in multiple blocks).
    for g in groups.values():
        seen = set()
        uniq = []
        for r in g['triggers']:
            key = (r.src, r.tgt, r.cls, tuple(sorted(r.perms)))
            if key not in seen:
                seen.add(key)
                uniq.append(r)
        g['triggers'] = uniq
    return groups


def validate_policy(rom_root: Path,
                    cil_paths: list,
                    full_rebuild: bool = False,
                    dry_run: bool = False) -> int:
    """Top-level driver for --validate / --validate-full.

       Returns 0 on clean exit (no issues OR all repairs accepted +
       applied), 1 if the user declined or any unrepairable issue
       remained.

       `cil_paths` is a list of (label, Path) tuples — the same shape
       passed to find_neverallow_conflicts.
    """
    print("\n" + "=" * 70)
    mode = 'full rebuild' if full_rebuild else 'surgical'
    print(f"[*] Validating policy ({mode} mode)")
    print(f"    rom-root: {rom_root}")
    for label, p in cil_paths:
        if p and p.exists():
            print(f"    target:   {label} {p}")
    print("=" * 70)

    if not cil_paths:
        print("[!] No CIL files to validate.")
        return 1

    # Build attr_map / all_types for empty-carveout resolution.
    attr_map: dict = {}
    all_types: set = set()
    for _, p in cil_paths:
        if not p or not p.exists():
            continue
        local_map = parse_cil_typeattributesets(p)
        local_types = collect_all_type_names(p)
        all_types.update(local_types)
        for k, v in local_map.items():
            if k in attr_map:
                attr_map[k] = ['or', attr_map[k], v]
            else:
                attr_map[k] = v

    # Scan for issues.
    issues = scan_validate_issues(cil_paths, attr_map=attr_map,
                                  all_types=all_types,
                                  full_rebuild=full_rebuild)

    if not issues:
        print("[OK] No issues detected.  Policy is clean.")
        return 0

    # Print all issues, grouped by file.
    by_file: dict = {}
    for iss in issues:
        by_file.setdefault(iss.cil_path, []).append(iss)

    total = len(issues)
    repairable = sum(1 for i in issues if i.repairable)
    print(f"\n[!] {total} issue(s) detected ({repairable} repairable, "
          f"{total - repairable} require manual review):")
    for cil_path, file_issues in by_file.items():
        print(f"\n  {cil_path}:")
        for iss in file_issues:
            tag = '[FIX]' if iss.repairable else '[MAN]'
            lines_str = (f"line {iss.line_nos[0]}"
                         if len(iss.line_nos) == 1
                         else f"lines {iss.line_nos[0]}-{iss.line_nos[-1]}")
            print(f"    {tag} {iss.kind} @ {lines_str}: {iss.description}")

    # Filter to repairable + group blocks by original for the repair pass.
    blocks_per_file: dict = {}
    for iss in issues:
        if not iss.repairable:
            continue
        if iss.block_info is None:
            continue
        live_ln = iss.block_info.get('live_line_no')
        if live_ln is None:
            continue
        blocks_per_file.setdefault(iss.cil_path, {})[live_ln] = iss.block_info

    # Also gather blocks for orphaned/empty/duplicate issues that don't
    # carry block_info but reference an aux_name — for these we'll do
    # plain comment-out repairs (no original to rebuild from).
    aux_cleanup_targets: dict = {}  # cil_path -> set(aux_name)
    for iss in issues:
        if not iss.repairable:
            continue
        if iss.kind in ('orphaned_aux_decl', 'empty_carveout',
                        'duplicate_aux_set'):
            if iss.aux_name:
                aux_cleanup_targets.setdefault(iss.cil_path,
                                               set()).add(iss.aux_name)

    groups = _group_blocks_by_original(blocks_per_file)

    print("\n" + "=" * 70)
    print(f"Repair plan:")
    print(f"  - Rebuild {len(groups)} neverallow exemption(s) from baseline")
    print(f"  - Comment out broken sepinject artifacts in {len(blocks_per_file)} file(s)")
    if aux_cleanup_targets:
        n_aux = sum(len(s) for s in aux_cleanup_targets.values())
        print(f"  - Comment out {n_aux} orphaned/empty/duplicate aux decl(s)")
    if dry_run:
        print(f"  - DRY RUN: no files will be modified")
    else:
        print(f"  - Files will be backed up to "
              f"<rom-root>/sepinject_validate_backup_<TS>/ first")
    print("=" * 70)

    try:
        ans = input("\nProceed with repair? [y/N]: ").strip().lower()
    except EOFError:
        ans = ''
    if ans not in ('y', 'yes'):
        print("[*] Repair declined; no changes made.")
        return 1

    # ---- Backup (skip on dry-run) ----
    if not dry_run:
        try:
            make_validate_backup(rom_root, cil_paths)
        except OSError as e:
            print(f"[!] Backup failed: {e}.  Aborting.")
            return 1

    # ---- Repair: rebuild groups from baseline ----
    # Strategy:
    #   1) For each group (per file, per original neverallow), parse the
    #      original text into a CilNeverallow, synthesize TeRules from the
    #      unioned triggers, and run find_neverallow_conflicts /
    #      apply_neverallow_rewrites to produce a clean rewrite.
    #
    #   2) BEFORE applying, comment out the OLD sepinject blocks (the
    #      live aux neverallow lines + audit comment chains) in each
    #      file so they don't fight with the new rewrites.  We leave
    #      the original `;; (neverallow ORIG ...)` lines alone — they
    #      stay as the audit anchor.
    #
    #   3) Comment out aux decls + sets for every aux_name referenced
    #      by the broken blocks AND for every aux flagged for cleanup
    #      (orphaned / empty / duplicate).

    rollback = RollbackSession()
    if dry_run:
        # Simulate without writes — just show the plan in more detail.
        for (cp, _), g in groups.items():
            print(f"\n  Would rebuild in {cp.name}: {g['original_text']}")
            print(f"    Triggers ({len(g['triggers'])}):")
            for r in g['triggers']:
                print(f"      allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}")
            print(f"    Blocks involved: {len(g['blocks'])}")
        for cp, names in aux_cleanup_targets.items():
            print(f"\n  Would clean up in {cp.name}: {sorted(names)}")
        print("\n[*] Dry-run complete.  Re-run without --dry-run to apply.")
        return 0

    # Live mode: perform the comment-out + inline rebuild in one pass.
    #
    # We cannot fall back to find_neverallow_conflicts + apply_neverallow_rewrites
    # here: their input is the set of LIVE `(neverallow ...)` lines in the
    # current file, and after cleanup those live lines are all gone (the
    # `;; (neverallow ORIG ...)` audit comments stay commented out — they
    # are the audit anchor, not policy).  So the rebuild has to be driven
    # directly from each group's recovered original + accumulated
    # triggers.  This is the inline version of the same machinery the
    # normal patch flow runs.

    # Build per-file aux cleanup targets (decls + sets to comment out)
    # from broken blocks' aux names + the standalone aux_cleanup_targets
    # (orphaned/empty/duplicate).
    files_to_modify: set = (set(blocks_per_file.keys())
                            | set(aux_cleanup_targets.keys()))
    auxes_to_comment_per_file: dict = {}
    for cp, blocks in blocks_per_file.items():
        s = auxes_to_comment_per_file.setdefault(cp, set())
        for info in blocks.values():
            if info.get('aux_name'):
                s.add(info['aux_name'])
    for cp, names in aux_cleanup_targets.items():
        s = auxes_to_comment_per_file.setdefault(cp, set())
        s.update(names)

    # Transitive cleanup expansion:
    # Build a graph of sepinject_aux_X -> {sepinject_aux_Y referenced by
    # X's typeattributeset body}.  Any aux that, after the initial
    # cleanup, has no LIVE references from outside the cleanup set
    # becomes itself orphaned (its membership computation is dead code).
    # We add such auxes to the cleanup until the fixpoint is reached.
    # This handles the deep-cascade case: Run 1's aux remains declared
    # after we clean up Run 2 and Run 3, but is now only referenced by
    # commented-out Run 2 — it should be cleaned up too.
    aux_refs: dict = {}   # aux_name -> set of sepinject_aux_* it references
    aux_locations: dict = {}  # aux_name -> list of (cil_path, line_no) for ta+tas
    aux_set_lines_by_file: dict = {}  # cil_path -> { aux_name -> body_node }
    aux_tas_re_local = re.compile(
        r'^\s*\(\s*typeattributeset\s+(sepinject_aux_[A-Za-z0-9_]+)\b',
    )
    aux_ta_re_local = re.compile(
        r'^\s*\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)',
    )
    for _, p in cil_paths:
        if not p or not p.exists():
            continue
        aux_set_lines_by_file[p] = {}
        for raw in p.read_text(errors='replace').splitlines():
            sl = raw.lstrip()
            if not sl or sl.startswith(';'):
                continue
            m_ta = aux_ta_re_local.match(raw)
            if m_ta:
                aux_locations.setdefault(m_ta.group(1), []).append((p, None))
                continue
            m_tas = aux_tas_re_local.match(raw)
            if m_tas:
                aux_name = m_tas.group(1)
                sexpr = _na_parse_sexpr_one(raw)
                refs: set = set()
                if (isinstance(sexpr, list) and len(sexpr) >= 3
                        and sexpr[0] == 'typeattributeset'):
                    def _collect(node):
                        if isinstance(node, str):
                            if node.startswith('sepinject_aux_'):
                                refs.add(node)
                            return
                        if isinstance(node, list):
                            for c in node:
                                _collect(c)
                    _collect(sexpr[2])
                refs.discard(aux_name)  # don't self-reference
                aux_refs[aux_name] = refs
                aux_set_lines_by_file[p][aux_name] = sexpr[2] if (
                    isinstance(sexpr, list) and len(sexpr) >= 3) else None

    # Set of all currently-flagged auxes (across files).
    flagged: set = set()
    for s in auxes_to_comment_per_file.values():
        flagged.update(s)

    # Reverse-reference map: aux_name -> set of auxes whose
    # typeattributeset body references it.
    reverse_refs: dict = {}
    for src, dests in aux_refs.items():
        for d in dests:
            reverse_refs.setdefault(d, set()).add(src)

    # Iterate: an aux is transitively-orphaned if its only referrers are
    # already in `flagged` AND no live (non-cascade) neverallow references
    # it.  We approximate "no live neverallow references it" by checking
    # whether it appears in the original all_live_aux_refs map outside
    # the cleanup blocks — but for simplicity, since the cleanup blocks
    # ARE all the live aux-based neverallows we know about, any sepinject_aux_*
    # we built the reverse map for is either referenced by another aux
    # or by a live neverallow we'll be cleaning up (block aux_names).
    # So: an aux is transitively orphaned iff (referrers \ flagged) is
    # empty AND aux is not used by any live neverallow we are KEEPING.
    # The block aux_names are the live neverallow references; everything
    # else with a typeattributeset is reachable only via auxes.
    block_aux_names: set = set()
    for cp, blocks in blocks_per_file.items():
        for info in blocks.values():
            if info.get('aux_name'):
                block_aux_names.add(info['aux_name'])

    changed = True
    while changed:
        changed = False
        for aux_name in list(aux_refs.keys()):
            if aux_name in flagged:
                continue
            # Is this aux referenced by a live neverallow we are KEEPING?
            # We only know about live neverallow refs that are part of a
            # sepinject block (block_aux_names).  All block aux_names are
            # being cleaned up, so any aux NOT in block_aux_names has no
            # live neverallow ref (in our problem domain).
            if aux_name in block_aux_names:
                continue  # has a live neverallow ref (being cleaned)
            referrers = reverse_refs.get(aux_name, set())
            external_refs = referrers - flagged
            if not external_refs:
                # Transitively orphaned — add to cleanup.
                flagged.add(aux_name)
                changed = True

    # Distribute newly-flagged auxes back to the per-file cleanup sets.
    for aux_name in flagged:
        for cp, body_map in aux_set_lines_by_file.items():
            if aux_name in body_map or aux_name in [
                a for (path, _ln) in aux_locations.get(aux_name, [])
                if path == cp for a in [aux_name]
            ]:
                # Found this aux declared/defined in this file.
                auxes_to_comment_per_file.setdefault(cp, set()).add(aux_name)
                files_to_modify.add(cp)

    aux_registry: dict = {}
    aux_emitted: set = set()
    aux_fingerprints: dict = {}

    # Pre-populate aux_emitted with any aux names that are NOT being
    # cleaned up, so we don't accidentally collide with surviving decls.
    pre_existing_aux_re = re.compile(
        r'^\s*\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)',
        re.MULTILINE,
    )
    for _, p in cil_paths:
        if not p or not p.exists():
            continue
        cleanup_here = auxes_to_comment_per_file.get(p, set())
        for m in pre_existing_aux_re.finditer(p.read_text(errors='replace')):
            if m.group(1) not in cleanup_here:
                aux_emitted.add(m.group(1))

    # Build per-group rewrite plans, computing src_resolved against the
    # global attr_map so build_rewrite() can do its vacuity checks.
    plans_per_file: dict = {}  # cil_path -> list[(live_line_no, rewrite_str, original_audit_text)]
    for (cp, _), g in groups.items():
        orig_text = g['original_text']
        sexpr = _na_parse_sexpr_one(orig_text)
        if not (isinstance(sexpr, list) and len(sexpr) >= 4
                and sexpr[0] == 'neverallow'):
            print(f"  [!] Could not parse recovered original for {cp.name}: "
                  f"{orig_text!r} — skipping group")
            continue
        src_node = sexpr[1]
        tgt_node = sexpr[2]
        cls_perms = sexpr[3]
        if not (isinstance(cls_perms, list) and len(cls_perms) == 2):
            continue
        cls_name = cls_perms[0]
        perms_node = cls_perms[1]
        if isinstance(perms_node, str):
            perms = [perms_node]
        elif isinstance(perms_node, list):
            perms = [p for p in perms_node if isinstance(p, str)]
        else:
            continue
        if not isinstance(cls_name, str):
            continue
        src_str = _na_sexpr_to_str(src_node)
        tgt_str = _na_sexpr_to_str(tgt_node)

        # Resolve src set for vacuity checks.
        src_resolved = _na_resolve_set(src_node, attr_map, all_types)

        # Filter triggers to those actually in conflict with the original
        # (same class, matching perms, src in resolved src set).
        excluded_srcs: list = []
        matched_perms: set = set()
        triggering_rules_kept: list = []
        for r in g['triggers']:
            if r.cls != cls_name:
                continue
            r_matched = [p for p in r.perms if p in perms]
            if not r_matched:
                continue
            if src_resolved is not None and r.src not in src_resolved:
                continue
            triggering_rules_kept.append(r)
            matched_perms.update(r_matched)
            if r.src and r.src not in excluded_srcs:
                excluded_srcs.append(r.src)
        excluded_srcs.sort()

        if not triggering_rules_kept:
            # No actual conflicts — the original neverallow is fine as-is.
            # Restore by un-commenting the audit-trail original (so the
            # policy still constrains what it always did).  We mark this
            # by setting rewrite_str=None and letting the file walker
            # know to restore the line.
            for b in g['blocks']:
                plans_per_file.setdefault(cp, []).append(
                    (b['live_line_no'], None, orig_text))
            continue

        # Build a synthetic CilNeverallow + NeverallowConflict to feed
        # build_rewrite.  base_na.line_no is set to the FIRST block's
        # live line number; the file walker uses this to know where to
        # write the new rewrite.
        first_live = g['blocks'][0]['live_line_no']
        base_na = CilNeverallow(
            cil_path=cp,
            line_no=first_live,
            raw_line=orig_text,
            src_expr=src_str,
            tgt_expr=tgt_str,
            cls=cls_name,
            perms=perms,
        )
        canonical_rule = triggering_rules_kept[0]
        synth_conflict = NeverallowConflict(
            rule=canonical_rule,
            neverallow=base_na,
            matched_perms=sorted(matched_perms),
            structural=False,
            src_resolved=src_resolved,
        )
        rewrite = build_rewrite(
            synth_conflict,
            aux_registry=aux_registry,
            attr_map=attr_map,
            all_types=all_types,
            excluded_srcs=excluded_srcs,
            aux_fingerprints=aux_fingerprints,
        )
        triggers_summary = ', '.join(
            f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
            for r in triggering_rules_kept
        )
        for b in g['blocks']:
            plans_per_file.setdefault(cp, []).append(
                (b['live_line_no'], rewrite, triggers_summary))

    # Walk each file once, applying the plan.
    aux_decl_re = re.compile(
        r'^(\s*)\(\s*typeattribute\s+(sepinject_aux_[A-Za-z0-9_]+)\s*\)(.*)$'
    )
    aux_set_re = re.compile(
        r'^(\s*)\(\s*typeattributeset\s+(sepinject_aux_[A-Za-z0-9_]+)\b(.*)$'
    )

    for cil_path in files_to_modify:
        rollback.snapshot(cil_path)
        text = cil_path.read_text(errors='replace')
        lines = text.splitlines(keepends=True)
        plans = plans_per_file.get(cil_path, [])
        # Map live_line_no -> (rewrite_str, triggers_summary_or_orig)
        plan_at: dict = {ln: (rw, tr) for ln, rw, tr in plans}
        block_audit_lines: set = set()
        for info in blocks_per_file.get(cil_path, {}).values():
            block_audit_lines.update(info.get('block_line_nos', set()))
        auxes_here = auxes_to_comment_per_file.get(cil_path, set())

        out: list = []
        for idx, raw in enumerate(lines, start=1):
            stripped_nl = raw.rstrip('\r\n')
            line_ending = raw[len(stripped_nl):]
            if idx in plan_at:
                rewrite_str, extra = plan_at[idx]
                if rewrite_str is None:
                    # Original is fine — comment out the broken live line
                    # and write the original neverallow back as live.
                    out.append(';; sepinject: VALIDATE — broken block removed; original restored\n')
                    out.append(';; ' + raw)
                    out.append(f"{extra}{line_ending}")
                else:
                    # Replace the broken live line with: comment-out +
                    # fresh rewrite (audit trail preserved).
                    out.append(';; sepinject: VALIDATE — broken block commented out (rebuilt below)\n')
                    out.append(';; ' + raw)
                    out.append(f";; sepinject: triggered by: {extra}\n")
                    out.append(rewrite_str + line_ending)
                continue
            if idx in block_audit_lines:
                out.append(raw)
                continue
            s = raw.rstrip('\r\n')
            m_ta = aux_decl_re.match(s)
            m_tas = aux_set_re.match(s)
            if m_ta and m_ta.group(2) in auxes_here:
                out.append(';; sepinject: VALIDATE — broken aux decl commented out\n')
                out.append(';; ' + raw)
                continue
            if m_tas and m_tas.group(2) in auxes_here:
                out.append(';; sepinject: VALIDATE — broken aux set commented out\n')
                out.append(';; ' + raw)
                continue
            out.append(raw)

        # Append any new aux decls produced by build_rewrite() to this
        # file's tail.  We only append the ones not already emitted.
        new_aux = [(n, d) for n, d in aux_registry.items()
                   if n not in aux_emitted]
        if new_aux:
            out.append('\n')
            out.append(';\n')
            out.append('; --- sepinject auxiliary attributes (rebuilt by --validate) ---\n')
            out.append(';\n')
            for aux_name, (ta_line, tas_line) in new_aux:
                out.append(ta_line + '\n')
                out.append(tas_line + '\n')
                aux_emitted.add(aux_name)
        cil_path.write_text(''.join(out))
        print(f"  [+] Rebuilt {cil_path.name} "
              f"({sum(1 for p in plans if p[1] is not None)} rewrite(s), "
              f"{sum(1 for p in plans if p[1] is None)} restore(s), "
              f"{len(auxes_here)} aux clean-up(s), "
              f"{len(new_aux)} new aux decl(s))")

    rollback.commit()
    return 0


# ===========================================================================


# ===========================================================================
# --rebuild-neverallows : recovery mode
# ===========================================================================
#
# Purpose
# -------
# When a sepolicy has been heavily user-modified (rules manually appended
# below a `; ~~~:BEGIN_MODS:~~~` marker) and the CIL has stopped compiling
# because of neverallow violations, this driver re-runs the same pre-flight
# neverallow logic the normal patch flow uses — BUT it sources the
# "proposed allow rules" directly from the user's existing modifications
# in the CIL file itself (everything below the BEGIN_MODS marker).  No
# external .te file is required.
#
# Assumed precondition
# --------------------
# The user has already manually:
#   1. Removed every sepinject_aux_* attribute decl / typeattributeset
#      from prior rewrite runs.
#   2. Un-commented the `;; (neverallow ...)` originals that were
#      previously rewritten, restoring them as live `(neverallow ...)`
#      statements.
#   3. Left their `(allow ...)` rules in place below the BEGIN_MODS
#      marker, so we know what to re-check against.
# We do NOT verify any of this — we just trust the input and process
# whatever is there.  (parse_cil_neverallows / find_neverallow_conflicts
# are robust to leftover sepinject blocks anyway; they'll just be detected
# as previously-rewritten and handled by the existing extend path.)
#
# Backups
# -------
# Every CIL file that could be modified is copied into
# `<rom-root>/sepinject_rebuild_neverallows_backup_<TS>/` BEFORE any
# write occurs.  Under --dry-run no backup is made and no file is touched.

REBUILD_MODS_MARKER_DEFAULT = '; ~~~:BEGIN_MODS:~~~'

# Substring form used to detect the marker regardless of surrounding
# whitespace.  The mods marker delimits the sepinject-managed region of a
# CIL file; downstream suite tools (SEPclean compaction/dedup, SEPwalk
# --rebuild-neverallows) locate the mods region by this substring, so
# patch_cil lays one down before the first modification to a virgin file.
MODS_MARKER_SUBSTR = '~~~:BEGIN_MODS:~~~'

# Matches a single-line CIL allow statement, e.g.:
#   (allow shell fuse (file (read open)))
# Captures: 1=src, 2=tgt, 3=cls, 4=raw perms string.
# We deliberately do NOT match auditallow / dontaudit — neverallow only
# constrains the `allow` AVRULE, so the rebuild scan only cares about
# allow rules.
_REBUILD_ALLOW_RE = re.compile(
    r'^\s*\(\s*allow\s+'
    r'(\S+)\s+'                # src
    r'(\S+)\s+'                # tgt
    r'\(\s*(\S+)\s+'           # cls
    r'\(\s*([^)]*?)\s*\)\s*\)' # perms
    r'\s*\)\s*$'
)


def parse_cil_mods_allow_rules(cil_path: Path,
                               marker: str = REBUILD_MODS_MARKER_DEFAULT) -> list:
    """Extract all single-line `(allow src tgt (cls (perms)))` statements
       from `cil_path` that appear AT OR BELOW the line containing `marker`.

       Returns a list of TeRule(op='allow', ...) objects.  Returns an empty
       list if the marker is absent (caller treats this as "no user mods to
       check in this file").

       Lines starting with `;` (CIL comments) are ignored, so commented-out
       allows do not trigger phantom rewrites.

       Multi-line allow statements are not supported by AOSP CIL emitters in
       practice and are skipped with a warning so the user knows the scan
       was incomplete on that line.
    """
    if not cil_path.exists():
        return []

    text = cil_path.read_text(errors='replace')
    lines = text.splitlines()

    # Find the marker line.  Tolerate leading/trailing whitespace.
    marker_norm = marker.strip()
    mods_start: Optional[int] = None
    for i, ln in enumerate(lines):
        if ln.strip() == marker_norm:
            mods_start = i + 1   # everything strictly below the marker line
            break
    if mods_start is None:
        return []

    rules: list = []
    skipped = 0
    for i in range(mods_start, len(lines)):
        raw = lines[i]
        stripped = raw.lstrip()
        if not stripped or stripped.startswith(';'):
            continue
        # Cheap prefix check before regex
        if not stripped.startswith('(allow'):
            continue
        # Paren balance: detect multi-line forms and skip
        if raw.count('(') != raw.count(')'):
            skipped += 1
            continue
        m = _REBUILD_ALLOW_RE.match(raw)
        if not m:
            skipped += 1
            continue
        src, tgt, cls, perms_str = m.group(1), m.group(2), m.group(3), m.group(4)
        perms = [p for p in perms_str.split() if p]
        if not perms:
            continue
        rules.append(TeRule(op='allow', src=src, tgt=tgt, cls=cls, perms=perms))

    if skipped:
        print(f"  [~] {cil_path.name}: {skipped} mod-section allow line(s) "
              f"skipped (multi-line or unparseable)")
    return rules


def find_rom_sepolicy_cils(rom_root: Path, plat_only: bool = False) -> list:
    """Return the fixed, well-known set of CIL files this tool already
       touches under `rom_root`.  This is NOT a recursive search and NOT
       a glob — it resolves the same four explicit paths the existing
       pre-flight neverallow check in main() resolves, no more and no
       less.  Returns a list of (label, Path) tuples in the shape
       expected by find_neverallow_conflicts / make_validate_backup.

       Recursive globbing was intentionally avoided: it would (a) drag
       in unrelated *.cil files the tool has no business modifying, and
       (b) on a re-run, sweep up files from a previous run's
       sepinject_rebuild_neverallows_backup_<TS>/ directory (which lives
       under rom_root), corrupting both the scan and any new backup.

       The four resolved paths, when present, are:
         - <rom_root>/<ROM_SYSTEM_SELINUX>/plat_sepolicy.cil
         - <rom_root>/<ROM_SYSTEM_EXT_SELINUX>/system_ext_sepolicy.cil
         - <rom_root>/<ROM_VENDOR_SELINUX>/vendor_sepolicy.cil
         - <rom_root>/<ROM_VENDOR_SELINUX>/plat_pub_versioned.cil
           (vendor partition; holds versioned plat-side neverallows
           that must also be honored on a CIL recompile — note the
           name does NOT follow the `<part>_sepolicy.cil` pattern,
           which is why it's enumerated explicitly here.)

       When `plat_only` is True, only plat_sepolicy.cil is returned —
       matches the semantics of the existing --plat-cil-only flag.
    """
    out: list = []
    sys_sel = rom_root / ROM_SYSTEM_SELINUX
    if sys_sel.is_dir():
        p = sys_sel / 'plat_sepolicy.cil'
        if p.exists():
            out.append(('plat', p))
    if plat_only:
        return out
    sext_sel = rom_root / ROM_SYSTEM_EXT_SELINUX
    if sext_sel.is_dir():
        p = sext_sel / 'system_ext_sepolicy.cil'
        if p.exists():
            out.append(('system_ext', p))
    vnd_sel = rom_root / ROM_VENDOR_SELINUX
    if vnd_sel.is_dir():
        p = vnd_sel / 'vendor_sepolicy.cil'
        if p.exists():
            out.append(('vendor', p))
        # plat_pub_versioned.cil lives on the vendor partition but holds
        # versioned plat-side neverallows; include it so a rebuild also
        # covers conflicts that would trip the recompile from that file.
        ppv = vnd_sel / 'plat_pub_versioned.cil'
        if ppv.exists():
            out.append(('plat_pub_versioned', ppv))
    return out


def make_rebuild_neverallows_backup(rom_root: Path, cil_paths: list) -> Path:
    """Snapshot every CIL file in `cil_paths` into
       <rom_root>/sepinject_rebuild_neverallows_backup_<TS>/ , mirroring
       the relative path layout under rom_root.

       Modelled after make_validate_backup() but with a distinct name so
       the user can tell which operation created the backup.
    """
    ts = time.strftime('%Y%m%d_%H%M%S')
    backup_dir = rom_root / f'sepinject_rebuild_neverallows_backup_{ts}'
    backup_dir.mkdir(parents=True, exist_ok=False)
    n = 0
    for entry in cil_paths:
        p = entry[1] if isinstance(entry, tuple) else entry
        if not p or not p.exists():
            continue
        try:
            rel = p.resolve().relative_to(rom_root.resolve())
        except ValueError:
            rel = Path('external') / p.name
        dest = backup_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        n += 1
    print(f"  [+] Backed up {n} CIL file(s) to: {backup_dir}")
    return backup_dir


def rebuild_neverallows(rom_root: Path,
                        dry_run: bool = False,
                        skip_sha256: bool = False,
                        plat_only: bool = False,
                        assume_yes: bool = False,
                        marker: str = REBUILD_MODS_MARKER_DEFAULT) -> int:
    """Top-level driver for --rebuild-neverallows.

       Returns 0 on success / no conflicts, 1 on failure, 2 if the user
       declined an interactive rewrite prompt.
    """
    print("\n" + "=" * 70)
    print(f"[*] Rebuilding neverallow carve-outs from existing CIL mods")
    print(f"    rom-root:     {rom_root}")
    print(f"    mods-marker:  {marker!r}")
    print(f"    dry-run:      {dry_run}")
    print(f"    skip-sha256:  {skip_sha256}")
    print(f"    plat-only:    {plat_only}")
    print(f"    assume-yes:   {assume_yes}")
    print("=" * 70)

    cil_paths = find_rom_sepolicy_cils(rom_root, plat_only=plat_only)
    if not cil_paths:
        print(f"[!] No *sepolicy.cil files found under {rom_root}.  Nothing to do.")
        return 1
    for label, p in cil_paths:
        print(f"    target:   {label:<20s} {p}")

    # ---- Phase 1: extract user mods from every CIL file with the marker ----
    print("\n[*] Extracting user-mod allow rules below marker")
    all_rules: list = []
    files_with_mods: list = []
    for label, p in cil_paths:
        rules = parse_cil_mods_allow_rules(p, marker=marker)
        if rules:
            print(f"  [+] {label}: {len(rules)} allow rule(s) below marker")
            all_rules.extend(rules)
            files_with_mods.append((label, p))
        else:
            print(f"  [~] {label}: no marker or no allow rules below it")

    if not all_rules:
        print("\n[OK] No user-mod allow rules detected — nothing to rebuild.")
        return 0

    print(f"\n[*] Total user-mod allow rules collected: {len(all_rules)}")

    # ---- Phase 2: conflict scan against full set of CIL neverallows ----
    print("\n[*] Scanning CIL files for neverallow conflicts")
    conflicts, na_attr_map, na_all_types = find_neverallow_conflicts(
        all_rules, cil_paths)

    if not conflicts:
        print("\n[OK] No neverallow conflicts detected — sepolicy is already clean "
              "with respect to the mods below the marker.")
        return 0

    print(f"\n[!] {len(conflicts)} neverallow conflict(s) found")

    # ---- Phase 3: dry-run preview ----
    if dry_run:
        print("\n--- Dry-run preview (no files will be written) ---")
        for i, c in enumerate(conflicts, 1):
            rule = c.rule
            na = c.neverallow
            print(f"\n  Conflict {i}:")
            print(f"    Mod allow: allow {rule.src} {rule.tgt}:{rule.cls} "
                  f"{{ {' '.join(rule.perms)} }};")
            print(f"    Violates:  {na.raw_line.strip()}")
            print(f"    Source:    {na.cil_path}:{na.line_no}")
            print(f"    Matched:   perm(s) {{ {' '.join(c.matched_perms)} }}")
            try:
                print(f"    Proposed:  {build_rewrite(c)}")
            except Exception as e:
                print(f"    Proposed:  (rewrite preview failed: {e})")
        print("\n[OK] Dry-run complete — re-run without --dry-run to apply.")
        return 0

    # ---- Phase 4: interactive (or auto-approve) confirmation ----
    if assume_yes:
        print("\n[*] --yes/--assume-yes was passed — skipping confirmation prompt.")
        proceed = True
    else:
        proceed = prompt_neverallow_conflicts(conflicts, binary_findings=[])

    if not proceed:
        print("\n[!] User declined — no files modified.")
        return 2

    # ---- Phase 5: backup every CIL file that could be touched ----
    print("\n[*] Backing up CIL files before modification")
    try:
        make_rebuild_neverallows_backup(rom_root, cil_paths)
    except OSError as e:
        print(f"[!] Backup failed: {e} — aborting before any modification.")
        return 1

    # ---- Phase 6: apply rewrites via the existing machinery ----
    rollback = RollbackSession()
    print(f"[*] Rollback snapshot dir: {rollback.session_dir}")
    # Pre-snapshot every CIL file (rewriter also snapshots, but doing it
    # up-front gives a single coherent restore point).
    for _, p in cil_paths:
        if p and p.exists():
            rollback.snapshot(p)
    # SHA-256 sidecars will also change — snapshot them.
    sys_sel = rom_root / ROM_SYSTEM_SELINUX
    sext_sel = rom_root / ROM_SYSTEM_EXT_SELINUX
    vnd_sel = rom_root / ROM_VENDOR_SELINUX
    if sys_sel.is_dir():
        rollback.snapshot(sys_sel / 'plat_sepolicy_and_mapping.sha256')
    if vnd_sel.is_dir():
        rollback.snapshot(vnd_sel /
                          'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256')
    if sext_sel.is_dir():
        rollback.snapshot(sext_sel / 'system_ext_sepolicy_and_mapping.sha256')
        if vnd_sel.is_dir():
            rollback.snapshot(vnd_sel /
                              'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256')

    try:
        rewrite_results = apply_neverallow_rewrites(
            conflicts, rollback,
            all_cil_paths=cil_paths,
            attr_map=na_attr_map,
            all_types=na_all_types,
        )
        all_rewrites_ok = (all(rewrite_results.values())
                           if rewrite_results else True)
    except Exception as e:
        print(f"\n[!] Neverallow rewrite failed: {e}")
        rollback.revert()
        return 1

    # ---- Phase 7: SHA-256 update ----
    sha_ok: Optional[bool] = None
    if not skip_sha256 and all_rewrites_ok:
        sys_selinux_dir = sys_sel if sys_sel.is_dir() else None
        vendor_selinux_dir = vnd_sel if vnd_sel.is_dir() else None
        sext_selinux_dir = sext_sel if sext_sel.is_dir() else None
        if sys_selinux_dir:
            sha_ok = update_sha256(sys_selinux_dir,
                                   vendor_selinux_dir,
                                   sext_selinux_dir)
        else:
            print("[~] No system selinux dir — skipping SHA-256 update")

    # ---- Phase 8: summary + rollback finalization ----
    print("\n" + "=" * 60)
    print("[*] Summary")
    print("=" * 60)
    print(f"    Conflicts processed: {len(conflicts)}")
    print(f"    CIL files rewritten: "
          f"{sum(1 for v in (rewrite_results or {}).values() if v)}")
    if sha_ok is True:
        print(f"    SHA-256 sidecars:    updated")
    elif sha_ok is False:
        print(f"    SHA-256 sidecars:    FAILED to update")
    else:
        print(f"    SHA-256 sidecars:    skipped")

    if all_rewrites_ok and (skip_sha256 or sha_ok is not False):
        rollback.commit()
        print("\n[OK] Rebuild complete.")
        return 0
    else:
        print(f"\n[!] One or more steps failed; pre-run snapshot is available at:")
        print(f"    {rollback.session_dir}")
        print(f"    ({len(rollback.snapshots)} file(s)).  Manual restore if needed.")
        return 1


# ===========================================================================


def make_recreate_mlsconstrains_backup(rom_root: Path, cil_paths: list) -> Path:
    """Snapshot every CIL file in `cil_paths` into
       <rom_root>/sepinject_recreate_mlsconstrains_backup_<TS>/ , mirroring
       the relative path layout.  Modelled on make_rebuild_neverallows_backup
       with a distinct name so the user can tell which operation ran."""
    ts = time.strftime('%Y%m%d_%H%M%S')
    backup_dir = rom_root / f'sepinject_recreate_mlsconstrains_backup_{ts}'
    backup_dir.mkdir(parents=True, exist_ok=False)
    n = 0
    for entry in cil_paths:
        p = entry[1] if isinstance(entry, tuple) else entry
        if not p or not p.exists():
            continue
        try:
            rel = p.resolve().relative_to(rom_root.resolve())
        except ValueError:
            rel = Path('external') / p.name
        dest = backup_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        n += 1
    print(f"  [+] Backed up {n} CIL file(s) to: {backup_dir}")
    return backup_dir


def recreate_mlsconstrains(rom_root: Path,
                           dry_run: bool = False,
                           skip_sha256: bool = False,
                           plat_only: bool = False,
                           assume_yes: bool = False,
                           marker: str = REBUILD_MODS_MARKER_DEFAULT,
                           only_domain: Optional[str] = None) -> int:
    """Top-level driver for --recreate-mlsconstrains.

       When `only_domain` is set (via --recreate-mls-domain), the extracted
       mod allow rules are filtered to that single source domain before the
       conflict scan, so only the constraints that actually block THAT domain
       are widened — instead of exempting every mod subject at once.

       The MLS analogue of rebuild_neverallows(): scan the same fixed set of
       ROM CIL files, extract every `(allow ...)` below the mods marker, and
       re-run the mlsconstrain conflict check against the FULL set of MLS
       constraints in those files.  Conflicts are rewritten via the same
       widen-with-exemption machinery used by the inline --check-mlsconstrains
       pre-flight.  Standalone; requires --rom-root.

       Returns 0 on success / no conflicts, 1 on failure, 2 if the user
       declined an interactive rewrite prompt.
    """
    print("\n" + "=" * 70)
    print(f"[*] Recreating mlsconstrain exemptions from existing CIL mods")
    print(f"    rom-root:     {rom_root}")
    print(f"    mods-marker:  {marker!r}")
    print(f"    dry-run:      {dry_run}")
    print(f"    skip-sha256:  {skip_sha256}")
    print(f"    plat-only:    {plat_only}")
    print(f"    assume-yes:   {assume_yes}")
    print(f"    only-domain:  {only_domain!r}")
    print("=" * 70)

    cil_paths = find_rom_sepolicy_cils(rom_root, plat_only=plat_only)
    if not cil_paths:
        print(f"[!] No *sepolicy.cil files found under {rom_root}.  Nothing to do.")
        return 1
    for label, p in cil_paths:
        print(f"    target:   {label:<20s} {p}")

    # ---- Phase 1: extract user-mod allow rules below the marker ----
    print("\n[*] Extracting user-mod allow rules below marker")
    all_rules: list = []
    for label, p in cil_paths:
        rules = parse_cil_mods_allow_rules(p, marker=marker)
        if rules:
            print(f"  [+] {label}: {len(rules)} allow rule(s) below marker")
            all_rules.extend(rules)
        else:
            print(f"  [~] {label}: no marker or no allow rules below it")

    if only_domain:
        before = len(all_rules)
        all_rules = [r for r in all_rules if r.src == only_domain]
        print(f"  [*] Filtered to domain {only_domain!r}: "
              f"{len(all_rules)}/{before} allow rule(s) match")

    if not all_rules:
        if only_domain:
            print(f"\n[OK] No mod allow rules for domain {only_domain!r} — "
                  f"nothing to recreate.")
        else:
            print("\n[OK] No user-mod allow rules detected — nothing to recreate.")
        return 0

    print(f"\n[*] Total user-mod allow rules collected: {len(all_rules)}")

    # ---- Phase 2: mlsconstrain conflict scan ----
    print("\n[*] Scanning CIL files for mlsconstrain conflicts")
    conflicts, mc_attr_map, mc_all_types = find_mlsconstrain_conflicts(
        all_rules, cil_paths)

    if not conflicts:
        print("\n[OK] No mlsconstrain conflicts detected — every mod allow is "
              "already permitted by the MLS constraints (via type clauses).")
        return 0

    print(f"\n[!] {len(conflicts)} mlsconstrain conflict(s) found")

    # ---- Phase 3: dry-run preview ----
    if dry_run:
        print("\n--- Dry-run preview (no files will be written) ---")
        for i, c in enumerate(conflicts, 1):
            rule = c.rule
            mc = c.mlsconstrain
            print(f"\n  Conflict {i}:")
            print(f"    Mod allow: allow {rule.src} {rule.tgt}:{rule.cls} "
                  f"{{ {' '.join(rule.perms)} }};")
            print(f"    Constraint:(mlsconstrain ({mc.cls} "
                  f"{{ {' '.join(mc.perms)} }}) {mc.expr_text})")
            print(f"    Source:    {mc.cil_path}:{mc.line_no}")
            print(f"    Matched:   perm(s) {{ {' '.join(c.matched_perms)} }}")
            print(f"    Verdict:   {c.verdict}")
            try:
                print(f"    Proposed:  {build_mls_rewrite(c)}")
            except Exception as e:
                print(f"    Proposed:  (rewrite preview failed: {e})")
        print("\n[OK] Dry-run complete — re-run without --dry-run to apply.")
        return 0

    # ---- Phase 4: confirmation ----
    if assume_yes:
        print("\n[*] --yes/--assume-yes was passed — skipping confirmation prompt.")
        proceed = True
    else:
        proceed = prompt_mlsconstrain_conflicts(conflicts)

    if not proceed:
        print("\n[!] User declined — no files modified.")
        return 2

    # ---- Phase 5: backup ----
    print("\n[*] Backing up CIL files before modification")
    try:
        make_recreate_mlsconstrains_backup(rom_root, cil_paths)
    except OSError as e:
        print(f"[!] Backup failed: {e} — aborting before any modification.")
        return 1

    # ---- Phase 6: apply ----
    rollback = RollbackSession()
    print(f"[*] Rollback snapshot dir: {rollback.session_dir}")
    for _, p in cil_paths:
        if p and p.exists():
            rollback.snapshot(p)
    sys_sel = rom_root / ROM_SYSTEM_SELINUX
    sext_sel = rom_root / ROM_SYSTEM_EXT_SELINUX
    vnd_sel = rom_root / ROM_VENDOR_SELINUX
    if sys_sel.is_dir():
        rollback.snapshot(sys_sel / 'plat_sepolicy_and_mapping.sha256')
    if vnd_sel.is_dir():
        rollback.snapshot(vnd_sel /
                          'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256')
    if sext_sel.is_dir():
        rollback.snapshot(sext_sel / 'system_ext_sepolicy_and_mapping.sha256')
        if vnd_sel.is_dir():
            rollback.snapshot(vnd_sel /
                              'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256')

    try:
        rewrite_results = apply_mlsconstrain_rewrites(
            conflicts, rollback,
            all_cil_paths=cil_paths,
            attr_map=mc_attr_map,
            all_types=mc_all_types,
        )
        all_rewrites_ok = (all(rewrite_results.values())
                           if rewrite_results else True)
    except Exception as e:
        print(f"\n[!] mlsconstrain rewrite failed: {e}")
        rollback.revert()
        return 1

    # ---- Phase 7: SHA-256 ----
    sha_ok: Optional[bool] = None
    if not skip_sha256 and all_rewrites_ok:
        sys_selinux_dir = sys_sel if sys_sel.is_dir() else None
        vendor_selinux_dir = vnd_sel if vnd_sel.is_dir() else None
        sext_selinux_dir = sext_sel if sext_sel.is_dir() else None
        if sys_selinux_dir:
            sha_ok = update_sha256(sys_selinux_dir, vendor_selinux_dir,
                                   sext_selinux_dir)
        else:
            print("[~] No system selinux dir — skipping SHA-256 update")

    # ---- Phase 8: summary ----
    print("\n" + "=" * 60)
    print("[*] Summary")
    print("=" * 60)
    print(f"    Conflicts processed: {len(conflicts)}")
    print(f"    CIL files rewritten: "
          f"{sum(1 for v in (rewrite_results or {}).values() if v)}")
    if sha_ok is True:
        print(f"    SHA-256 sidecars:    updated")
    elif sha_ok is False:
        print(f"    SHA-256 sidecars:    FAILED to update")
    else:
        print(f"    SHA-256 sidecars:    skipped")

    if all_rewrites_ok and (skip_sha256 or sha_ok is not False):
        rollback.commit()
        print("\n[OK] mlsconstrain recreation complete.")
        return 0
    else:
        print(f"\n[!] One or more steps failed; pre-run snapshot is available at:")
        print(f"    {rollback.session_dir}")
        print(f"    ({len(rollback.snapshots)} file(s)).  Manual restore if needed.")
        return 1


# ----- Binary policy neverallow scan (read-only safety check) -----

def scan_binary_neverallows(helper: Path, policies: list) -> list:
    """For each binary policy in `policies`, run the helper in scan-only mode
       and collect any neverallow findings.  Returns a list of human-readable
       strings.

       This is purely informational — the tool does not modify binary
       policies based on findings.  Standard AOSP-built kernel binaries have
       zero entries (neverallow is compile-time only); the scan exists to
       surface non-standard vendor artifacts (e.g. MTK).
    """
    # (subprocess already imported by main script)

    findings: list = []
    if not policies:
        return findings

    # Build a tiny scan-only JSON payload
    scan_json = '[{"op":"scan_neverallows"}]'

    for pol in policies:
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False) as jf:
            jf.write(scan_json)
            jf_path = jf.name
        try:
            r = subprocess.run(
                [str(helper), jf_path, str(pol), '--scan-only'],
                capture_output=True, text=True
            )
        finally:
            try:
                Path(jf_path).unlink()
            except Exception:
                pass

        # Parse stderr for NEVERALLOW_FINDING and NEVERALLOW_SCAN_TOTAL lines
        total = 0
        local_findings = []
        for line in (r.stderr or '').splitlines():
            if line.startswith('NEVERALLOW_FINDING'):
                local_findings.append(line)
            elif line.startswith('NEVERALLOW_SCAN_TOTAL='):
                try:
                    total = int(line.split('=', 1)[1])
                except ValueError:
                    pass
        if total > 0:
            findings.append(f"{pol}: {total} entry/entries")
            findings.extend(f"  {pol.name}: {fl}" for fl in local_findings)
        else:
            print(f"  [OK] {pol.name}: 0 binary neverallow entries (expected)")

    return findings


# ---------------------------------------------------------------------------
# End of neverallow module
# ---------------------------------------------------------------------------


CACHE_DIR = Path.home() / '.cache' / 'sepinject'
HELPER_NAME = 'sepatch_helper'

LIBSEPOL_SOURCE_URL = "https://github.com/SELinuxProject/selinux/releases/download/3.7/libsepol-3.7.tar.gz"
LIBSEPOL_SOURCE_SHA256 = "7619b3b9483879bc8e9312da75d5c5e3f5e380fddd3fd73f3f2ccd7dc55b609b"


def _source_hash() -> str:
    return hashlib.sha256(HELPER_C_SOURCE.encode()).hexdigest()[:16]


INSTALL_HINT = """\
  Missing dependency: libsepol (headers + static library)

  Install the appropriate package for your distro, then re-run this tool:

    Arch / Manjaro   :  sudo pacman -S libsepol
    Debian / Ubuntu  :  sudo apt install libsepol-dev
    Fedora / RHEL    :  sudo dnf install libsepol-devel
    openSUSE         :  sudo zypper install libsepol-devel
    Gentoo           :  emerge sys-libs/libsepol

  After installing, delete the cached helper so it gets recompiled:
    rm -rf ~/.cache/sepinject/

  If libsepol is installed but compilation still fails, the static archive
  on your distro may use hidden symbol visibility. This tool automatically
  tries -Wl,--whole-archive to work around this. If you still see errors,
  check that gcc is installed:
    Arch:   sudo pacman -S gcc
    Debian: sudo apt install gcc
"""


def _run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _pkg_config(*args) -> Optional[str]:
    """Run pkg-config and return stdout, or None if unavailable/failed."""
    try:
        r = _run(['pkg-config'] + list(args))
        return r.stdout.strip() if r.returncode == 0 else None
    except FileNotFoundError:
        return None


def _find_headers() -> Optional[str]:
    """Return -I flag for the sepol headers, or None if already on default path."""
    # pkg-config is authoritative
    cflags = _pkg_config('--cflags', 'libsepol')
    if cflags is not None:
        return cflags  # may be empty string (headers in /usr/include — fine)

    # Manual search
    for d in ['/usr/include', '/usr/local/include']:
        if Path(d, 'sepol', 'policydb', 'policydb.h').exists():
            return f'-I{d}'

    return None  # caller will treat as missing


def _probe_link_args(src: Path, helper: Path) -> Optional[list[str]]:
    """
    Try several linker strategies in order and return the first that produces
    a working binary.  Returns None if all fail.

    Strategy order:
      1. Static .a via pkg-config  (Debian with libsepol-dev)
      2. Static .a at common paths  (Arch: /usr/lib/libsepol.a,
                                     Debian multiarch: /usr/lib/<triplet>/libsepol.a)
      2b. Same paths with -Wl,--whole-archive  (newer Arch where .a hides symbols)
      3. Dynamic -lsepol            (DSO exports all symbols)
      4. Dynamic via pkg-config     (any distro with pkg-config but no .a)
    """
    include_flag = _find_headers() or ''

    def try_compile(link_flags: list[str], label: str) -> bool:
        cmd = ['gcc', '-O2', '-Wno-unused-result',
               '-o', str(helper), str(src)] + \
              ([include_flag] if include_flag else []) + \
              link_flags
        r = _run(cmd)
        if r.returncode == 0:
            print(f"  [+] Linked with: {label}")
            if r.stderr.strip():
                print(f"  [~] {r.stderr.strip()}")
            return True
        return False

    import glob

    # 1. Static .a from pkg-config
    pc_static = _pkg_config('--static', '--libs', 'libsepol')
    if pc_static:
        pc_libdir = _pkg_config('--variable=libdir', 'libsepol') or ''
        if pc_libdir:
            a = Path(pc_libdir) / 'libsepol.a'
            if a.exists() and try_compile([str(a)], f'static {a}'):
                return [str(a)]
            # Try whole-archive in case symbols are hidden
            flags = ['-Wl,--whole-archive', str(a), '-Wl,--no-whole-archive']
            if a.exists() and try_compile(flags, f'whole-archive {a}'):
                return flags

    # 2. Static .a at well-known paths (covers Arch + all Debian multiarch triplets)
    static_candidates = (
        glob.glob('/usr/lib/libsepol.a') +
        glob.glob('/usr/local/lib/libsepol.a') +
        glob.glob('/usr/lib/*/libsepol.a') +        # Debian multiarch
        glob.glob('/usr/lib64/libsepol.a') +         # Fedora/openSUSE
        glob.glob('/usr/lib32/libsepol.a')
    )
    for a in static_candidates:
        if not Path(a).exists():
            continue
        # Plain static link
        if try_compile([a], f'static {a}'):
            return [a]
        # Whole-archive — required on newer Arch/Manjaro where libsepol.a
        # marks internal symbols as hidden even in the static archive
        flags = ['-Wl,--whole-archive', a, '-Wl,--no-whole-archive']
        if try_compile(flags, f'whole-archive {a}'):
            return flags

    # 3. Dynamic -lsepol
    libdirs = []
    pc_libdir = _pkg_config('--variable=libdir', 'libsepol')
    if pc_libdir:
        libdirs = [f'-L{pc_libdir}']
    if try_compile(libdirs + ['-lsepol'], 'dynamic -lsepol'):
        return libdirs + ['-lsepol']

    # 4. Full pkg-config ldflags as last resort
    pc_libs = _pkg_config('--libs', 'libsepol')
    if pc_libs:
        flags = pc_libs.split()
        if try_compile(flags, f'pkg-config: {pc_libs}'):
            return flags

    return None


def _build_libsepol_from_source() -> Optional[tuple[str, str]]:
    """
    Download, build, and install libsepol into the cache dir.
    Returns (include_flag, static_lib_path) or None on failure.
    Used as a fallback when the system libsepol can't be linked against.
    """
    import urllib.request, hashlib, tarfile

    build_dir = CACHE_DIR / 'libsepol_src'
    install_dir = CACHE_DIR / 'libsepol_install'
    static_lib = install_dir / 'lib' / 'libsepol.a'
    include_dir = install_dir / 'include'

    if static_lib.exists() and include_dir.exists():
        print(f"  [+] Using cached libsepol build: {install_dir}")
        return (f'-I{include_dir}', str(static_lib))

    print(f"  [*] Downloading libsepol source from GitHub…")
    tarball = CACHE_DIR / 'libsepol.tar.gz'
    try:
        urllib.request.urlretrieve(LIBSEPOL_SOURCE_URL, tarball)
    except Exception as e:
        print(f"  [!] Download failed: {e}")
        return None

    # Verify checksum
    sha = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if sha != LIBSEPOL_SOURCE_SHA256:
        print(f"  [!] Checksum mismatch: got {sha}")
        return None

    print("  [*] Extracting…")
    build_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball) as tf:
        tf.extractall(build_dir)

    src_dir = next(build_dir.iterdir())  # libsepol-3.7/
    install_dir.mkdir(parents=True, exist_ok=True)

    print("  [*] Building libsepol (this takes ~30 seconds)…")
    r = _run(['make', '-C', str(src_dir),
              f'DESTDIR={install_dir}', 'LIBDIR=/lib', 'INCLUDEDIR=/include',
              'install', '-j4'])
    if r.returncode != 0:
        print(f"  [!] Build failed:\n{r.stderr[-1000:]}")
        return None

    if not static_lib.exists():
        print(f"  [!] Static lib not found after build: {static_lib}")
        return None

    print(f"  [+] libsepol built successfully")
    return (f'-I{include_dir}', str(static_lib))


def get_or_compile_helper() -> Path:
    """
    Compile the C helper, auto-detecting libsepol on any distro.

    Detection order:
      1. pkg-config libdir  → explicit .a path        (any distro with pkg-config)
      2. Glob well-known .a locations + whole-archive  (Arch, Debian multiarch,
                                                        Fedora, openSUSE)
      3. Dynamic -lsepol                               (DSO exports all symbols)
      4. pkg-config --libs flags                       (catch-all)
      5. Build libsepol 3.7 from source                (universal fallback)

    If nothing works, prints distro-specific install instructions and exits.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    helper = CACHE_DIR / f'{HELPER_NAME}_{_source_hash()}'
    if helper.exists():
        return helper

    print("[*] Compiling C policy helper (first run)…")
    src = CACHE_DIR / 'sepatch_helper.c'
    src.write_text(HELPER_C_SOURCE)

    # Check headers are available
    include_flag = _find_headers()
    if include_flag is None:
        print("  [!] sepol headers not found. Attempting source build fallback…")
        result = _build_libsepol_from_source()
        if result is None:
            print("[!] sepol headers not found and source build failed.")
            print(INSTALL_HINT)
            raise SystemExit(1)
        inc, lib = result
        cmd = ['gcc', '-O2', '-Wno-unused-result', '-o', str(helper), str(src), inc, lib]
        r = _run(cmd)
        if r.returncode != 0:
            print(f"  [!] Compilation failed:\n{r.stderr}")
            raise SystemExit(1)
        helper.chmod(0o755)
        print(f"  [+] Helper compiled with source-built libsepol: {helper}")
        return helper

    # Headers found — probe for working linker strategy
    link_args = _probe_link_args(src, helper)
    if link_args is None:
        print("  [!] Could not link against system libsepol.")
        print("  [*] Attempting to build libsepol from source as fallback…")
        result = _build_libsepol_from_source()
        if result is None:
            print("[!] Source build also failed.")
            print(INSTALL_HINT)
            raise SystemExit(1)
        inc, lib = result
        cmd = ['gcc', '-O2', '-Wno-unused-result', '-o', str(helper), str(src), inc, lib]
        r = _run(cmd)
        if r.returncode != 0:
            print(f"  [!] Compilation failed:\n{r.stderr}")
            raise SystemExit(1)
        helper.chmod(0o755)
        print(f"  [+] Helper compiled with source-built libsepol: {helper}")
        return helper

    # _probe_link_args already produced a working binary
    helper.chmod(0o755)
    return helper


# ---------------------------------------------------------------------------
# Policy patching
# ---------------------------------------------------------------------------

def patch_policy(helper: Path, rules_json: str, policy_path: Path) -> bool:
    """Apply rules to a single binary policy file in-place."""
    if not policy_path.exists():
        print(f"  [!] Policy not found, skipping: {policy_path}")
        return False

    print(f"\n[*] Patching: {policy_path}")

    # Write rules to a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
        tf.write(rules_json)
        tf_path = tf.name

    # Backup original
    backup = policy_path.with_suffix(policy_path.suffix + '.bak')
    if not backup.exists():
        shutil.copy2(policy_path, backup)
        print(f"  [+] Backup: {backup}")

    try:
        result = subprocess.run(
            [str(helper), tf_path, str(policy_path)],
            capture_output=True, text=True
        )
        # Print helper stderr (its progress log)
        for line in result.stderr.splitlines():
            print(f"  {line}")
        if result.returncode != 0:
            print(f"  [!] Helper exited with code {result.returncode}")
            # Restore backup
            shutil.copy2(backup, policy_path)
            print(f"  [!] Restored from backup.")
            return False
        return True
    finally:
        os.unlink(tf_path)


def remove_rules_to_cil(rules: list[RemoveRule]) -> list[str]:
    """
    Build a list of CIL statement strings that should be REMOVED from
    plat_sepolicy.cil.  Returns strings that can be matched line-by-line.
    """
    targets = []
    for r in rules:
        if r.op == 'remove_allow':
            perms = ' '.join(r.perms)
            targets.append(f'(allow {r.src} {r.tgt} ({r.cls} ({perms})))')
        elif r.op == 'remove_genfscon':
            # Match both possible CIL forms we may have written
            targets.append(f'(genfscon {r.src} "{r.tgt}"')  # prefix match
        elif r.op == 'remove_permissive':
            targets.append(f'(typepermissive {r.type_name})')
        elif r.op == 'remove_type':
            targets.append(f'(type {r.type_name})')
            targets.append(f'(roletype object_r {r.type_name})')
            # Also remove typeattributeset lines that reference this type
            targets.append(f'({r.type_name})')  # suffix match in typeattributeset
        elif r.op == 'remove_typeattribute':
            targets.append(f'(typeattributeset {r.attr} ({r.type_name}))')
    return targets


def remove_from_cil(cil_path: Path, remove_rules: list[RemoveRule]) -> bool:
    """
    Remove CIL statements from plat_sepolicy.cil that correspond to
    the given RemoveRule list.

    Matching strategy per rule type:
      remove_allow      — exact line match
      remove_genfscon   — prefix match (handles MLS suffix variants)
      remove_permissive — exact line match
      remove_type       — exact line match for (type X), (roletype object_r X),
                          and any (typeattributeset Y (X)) lines
      remove_typeattribute — exact line match
    """
    if not cil_path.exists():
        print(f"  [!] CIL file not found, skipping removal: {cil_path}")
        return False

    print(f"\n[*] Removing CIL entries from: {cil_path}")

    backup = cil_path.with_suffix('.cil.bak')
    if not backup.exists():
        import shutil as _shutil
        _shutil.copy2(cil_path, backup)
        print(f"  [+] Backup: {backup}")

    original_lines = cil_path.read_text(errors='replace').splitlines(keepends=True)

    # Build removal targets
    exact_targets: set[str] = set()
    prefix_targets: list[str] = []
    # For remove_type we also need to purge typeattributeset lines containing the type
    type_names_to_remove: set[str] = set()

    for r in remove_rules:
        if r.op == 'remove_allow':
            perms = ' '.join(r.perms)
            exact_targets.add(f'(allow {r.src} {r.tgt} ({r.cls} ({perms})))')
        elif r.op == 'remove_genfscon':
            prefix_targets.append(f'(genfscon {r.src} "{r.tgt}"')
        elif r.op == 'remove_permissive':
            exact_targets.add(f'(typepermissive {r.type_name})')
        elif r.op == 'remove_type':
            type_names_to_remove.add(r.type_name)
            exact_targets.add(f'(type {r.type_name})')
            exact_targets.add(f'(roletype object_r {r.type_name})')
        elif r.op == 'remove_typeattribute':
            exact_targets.add(f'(typeattributeset {r.attr} ({r.type_name}))')

    kept_lines = []
    removed = 0

    for line in original_lines:
        stripped = line.strip()

        # Check exact match
        if stripped in exact_targets:
            print(f"  [-] Removed: {stripped}")
            removed += 1
            continue

        # Check prefix match (genfscon with MLS suffix)
        matched_prefix = False
        for pfx in prefix_targets:
            if stripped.startswith(pfx):
                print(f"  [-] Removed (prefix match): {stripped}")
                removed += 1
                matched_prefix = True
                break
        if matched_prefix:
            continue

        # Check typeattributeset lines referencing a type being removed
        # Pattern: (typeattributeset someattr (typename)) or similar
        if type_names_to_remove:
            # Match lines like: (typeattributeset fs_type (q25_led_sysfs))
            for tname in type_names_to_remove:
                # Match typeattributeset with this type as sole or partial member
                if re.search(
                    r'\(typeattributeset\s+\S+\s+\([^)]*\b' + re.escape(tname) + r'\b[^)]*\)\)',
                    stripped
                ):
                    print(f"  [-] Removed typeattributeset ref to '{tname}': {stripped}")
                    removed += 1
                    matched_prefix = True
                    break
            if matched_prefix:
                continue

        kept_lines.append(line)

    if removed == 0:
        print("  [~] No matching CIL statements found to remove")
        return True

    cil_path.write_text(''.join(kept_lines))
    print(f"  [+] Removed {removed} CIL statement(s)")
    return True


# ---------------------------------------------------------------------------
# CIL generation — translate TeRule objects into CIL syntax lines
# ---------------------------------------------------------------------------

def rules_to_cil(rules: list[TeRule]) -> str:
    """
    Translate a list of TeRule objects into CIL statements suitable for
    appending to plat_sepolicy.cil.

    CIL equivalents:
      allow src tgt:cls { perms }      -> (allow src tgt (cls (p1 p2 ...)))
      auditallow src tgt:cls { perms } -> (auditallow src tgt (cls (p1 p2 ...)))
      dontaudit src tgt:cls { perms }  -> (dontaudit src tgt (cls (p1 p2 ...)))
      permissive foo                   -> (typepermissive foo)
      type foo                         -> (type foo)\n(roletype object_r foo)
      attribute bar                    -> (typeattribute bar)
      typeattribute foo bar            -> (typeattributeset bar (foo))
      type_transition s t:c d          -> (typetransition s t c d)
    """
    lines = []
    lines.append('')
    lines.append(';')
    lines.append('; --- sepinject additions ---')
    lines.append(';')

    for r in rules:
        if r.op in ('allow', 'auditallow', 'dontaudit'):
            perms = ' '.join(r.perms)
            lines.append(f'({r.op} {r.src} {r.tgt} ({r.cls} ({perms})))')

        elif r.op == 'permissive':
            lines.append(f'(typepermissive {r.type_name})')

        elif r.op == 'type':
            # Every new type needs (type foo) + (roletype object_r foo)
            lines.append(f'(type {r.type_name})')
            lines.append(f'(roletype object_r {r.type_name})')
            if r.attr:
                lines.append(f'(typeattributeset {r.attr} ({r.type_name}))')

        elif r.op == 'attribute':
            lines.append(f'(typeattribute {r.type_name})')

        elif r.op == 'typeattribute':
            lines.append(f'(typeattributeset {r.attr} ({r.type_name}))')

        elif r.op == 'type_transition':
            # Named transitions use (typetransition src tgt cls name default)
            if r.tr_name:
                lines.append(
                    f'(typetransition {r.src} {r.tgt} {r.cls} "{r.tr_name}" {r.default})'
                )
            else:
                lines.append(f'(typetransition {r.src} {r.tgt} {r.cls} {r.default})')

        elif r.op == 'genfscon':
            # CIL: (genfscon fs "/path" (u object_r type ((s0) (s0))))
            # Parse context string u:object_r:mytype:s0 -> extract type
            parts = r.context.split(':')
            if len(parts) >= 3:
                ctx_type = parts[2]
                lines.append(
                    f'(genfscon {r.fs_type} "{r.path}" '
                    f'(u object_r {ctx_type} ((s0) (s0))))'
                )
            else:
                print(f'  [!] Cannot generate CIL for genfscon context: {r.context!r}')

    lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Multi-CIL helpers — coredomain attribution, attribute augmentation, vendor
# CIL augmentation.  See the long comment block at the top of this section
# for the motivation: the original script only patched plat_sepolicy.cil and
# could not handle the case where a new domain needs coredomain attribution
# (the dominant cause of CIL recompile failures when adding new domains).
# ---------------------------------------------------------------------------

# Heuristic markers — types declared with these attributes are domains.
# init_daemon_domain() expands to (typeattributeset domain (X)), so detecting
# either an explicit attribute=domain on a type or a typeattributeset rule
# adding the type to domain is equivalent.
_DOMAIN_ATTRS = {'domain', 'coredomain'}

# Attribute sets that new plat-side domains typically need membership in.
# coredomain is mandatory on Treble policy splits to satisfy plat-vs-vendor
# neverallows.  The other two are optional and only added when explicitly
# requested via CLI.  Adding to system_executes_vendor_violators is only
# correct when the new domain actually execs vendor binaries — most new
# plat domains do not, and adding it is a security relaxation.
_CORE_ATTRIBUTE = 'coredomain'

def detect_new_domains(rules: list) -> set[str]:
    """Identify type names in `rules` that are being declared as new domains.

    A type is treated as a domain if any of:
      - A `type X` rule has attr='domain' (or 'coredomain')
      - A `typeattribute X domain` rule appears
      - An init_daemon_domain-style transition targets the type as default
        in a process-class typetransition rule

    Returns the set of domain type names.  Used to drive auto-coredomain
    attribution and other domain-specific rule generation.
    """
    domains: set[str] = set()

    for r in rules:
        if r.op == 'type' and r.attr in _DOMAIN_ATTRS:
            domains.add(r.type_name)
        elif r.op == 'typeattribute' and r.attr in _DOMAIN_ATTRS:
            domains.add(r.type_name)
        elif r.op == 'type_transition' and r.cls == 'process':
            # init → exec → new_domain pattern; default is the new domain.
            domains.add(r.default)

    return domains


def synthesize_coredomain_rules(domains: set[str], existing_rules: list,
                                cil_paths: list | None = None) -> list:
    """Build a list of typeattribute rules placing `domains` into coredomain.

    Skips any domain that already has an explicit coredomain typeattribute
    rule in `existing_rules`, so this is safely idempotent when called
    repeatedly with the same input.

    If `cil_paths` is provided, each file is also scanned for existing
    coredomain membership.  Without this, `detect_new_domains` flags every
    process-class type_transition default as a "new domain" (e.g. a
    `type_transition pit_installer pit_launcher_exec:process shell;`
    classifies `shell` as a new domain), and a redundant
    `(typeattributeset coredomain (shell))` is emitted into the CIL.
    CIL accepts duplicate typeattributeset membership so this is not
    fatal, but it's noise we should suppress.

    Returns a list of synthetic TeRule objects.  Caller appends these to
    the main rules list before CIL emission.
    """
    if not domains:
        return []

    already_attributed: set[str] = set()
    for r in existing_rules:
        if r.op == 'typeattribute' and r.attr == _CORE_ATTRIBUTE:
            already_attributed.add(r.type_name)

    if cil_paths:
        # Scan live CIL for existing coredomain membership.  Two CIL forms
        # confer coredomain status:
        #   (typeattributeset coredomain (a b c))
        #   (typeattributeset coredomain (a))
        # We also accept multi-line forms by joining the inner group.
        tas_re = re.compile(
            r'\(\s*typeattributeset\s+coredomain\s+\(([^()]*)\)\s*\)',
            re.MULTILINE,
        )
        for entry in cil_paths:
            p = entry[1] if isinstance(entry, tuple) else entry
            try:
                txt = p.read_text(errors='replace')
            except OSError:
                continue
            for m in tas_re.finditer(txt):
                for tok in m.group(1).split():
                    already_attributed.add(tok.strip())

    needed = domains - already_attributed
    if not needed:
        return []

    synthetic: list = []
    for d in sorted(needed):
        synthetic.append(TeRule(
            op='typeattribute',
            type_name=d,
            attr=_CORE_ATTRIBUTE,
        ))
    return synthetic


def augment_typeattributeset_in_cil(cil_path: Path, attr_name: str,
                                     types_to_add: list[str]) -> bool:
    """Add type names to an existing (typeattributeset attr_name (...)) entry.

    Why this is needed beyond a simple `patch_cil` append: in some cases
    we don't want to *declare* a typeattributeset for an attribute that
    already exists in the file — we want to *extend* the existing entry's
    member list.  CIL allows multiple typeattributeset statements for the
    same attribute (their member lists are unioned at compile time), so an
    additional `(typeattributeset coredomain (pit_installer))` at the end
    of the file works.  But some vendor-side neverallow rules use exact
    string matching on the canonical coredomain list, in which case
    extending the original line is safer.

    This function looks for an existing line `(typeattributeset attr (...))`,
    appends the new types into the existing member list, and writes back.
    If no existing line is found, it appends a new typeattributeset line
    at the end.  Returns True on success.
    """
    if not cil_path.exists():
        print(f"  [!] CIL file not found, skipping: {cil_path}")
        return False

    if not types_to_add:
        return True

    text = cil_path.read_text(errors='replace')

    # Backup once
    backup = cil_path.with_suffix(cil_path.suffix + '.bak')
    if not backup.exists():
        shutil.copy2(cil_path, backup)

    # Find existing (typeattributeset <attr> (...)) — first occurrence wins.
    # The regex is intentionally simple; the canonical form is one line,
    # but we handle multi-line by collapsing whitespace within the parens.
    pattern = re.compile(
        r'\(typeattributeset\s+' + re.escape(attr_name) + r'\s+\(([^)]*)\)\s*\)',
        re.DOTALL,
    )
    m = pattern.search(text)

    if m:
        existing_members = m.group(1).split()
        new_members = [t for t in types_to_add if t not in existing_members]
        if not new_members:
            print(f"  [~] {attr_name} already contains all requested types in {cil_path.name}")
            return True
        combined = existing_members + new_members
        # Reformat: one space between members, original style.
        replacement = f'(typeattributeset {attr_name} ({" ".join(combined)}))'
        new_text = text[:m.start()] + replacement + text[m.end():]
        cil_path.write_text(new_text)
        print(f"  [+] Extended (typeattributeset {attr_name} ...) in {cil_path.name} "
              f"with: {' '.join(new_members)}")
        return True

    # No existing entry — append a fresh one
    new_block = f'\n(typeattributeset {attr_name} ({" ".join(types_to_add)}))\n'
    with open(cil_path, 'a') as f:
        f.write(new_block)
    print(f"  [+] Added new (typeattributeset {attr_name} ...) to {cil_path.name}")
    return True


def patch_vendor_cil_augmentations(vendor_cil_path: Path,
                                    augmentations: dict[str, list[str]]) -> bool:
    """Apply attribute-set augmentations to vendor_sepolicy.cil.

    `augmentations` maps attribute_name -> list of type names to add to
    that attribute set in the vendor CIL.  This is for cases where a new
    plat-side type needs to be visible to vendor-side rules via a vendor
    attribute set (e.g., adding pit_installer to a vendor-defined helper
    attribute).

    This does NOT add type declarations — type declaration goes in plat.
    It only extends existing attribute sets, which is safe because CIL
    typeattributeset statements union with prior ones at compile time.

    Returns True if all augmentations applied cleanly.
    """
    if not vendor_cil_path.exists():
        print(f"  [!] vendor_sepolicy.cil not found, skipping vendor augmentation")
        return False

    print(f"\n[*] Augmenting vendor CIL: {vendor_cil_path}")
    all_ok = True
    for attr_name, types_to_add in augmentations.items():
        if not types_to_add:
            continue
        ok = augment_typeattributeset_in_cil(vendor_cil_path, attr_name, types_to_add)
        if not ok:
            all_ok = False
    return all_ok


# ---------------------------------------------------------------------------
# plat_sepolicy.cil patching
# ---------------------------------------------------------------------------

def patch_cil(cil_path: Path, rules: list[TeRule]) -> bool:
    """
    Append CIL rules to plat_sepolicy.cil.
    Skips rules whose CIL statement is already present (idempotent).
    """
    if not cil_path.exists():
        print(f"  [!] CIL file not found, skipping: {cil_path}")
        return False

    print(f"\n[*] Patching CIL: {cil_path}")

    existing = cil_path.read_text(errors='replace')

    # Backup
    backup = cil_path.with_suffix('.cil.bak')
    if not backup.exists():
        shutil.copy2(cil_path, backup)
        print(f"  [+] Backup: {backup}")

    cil_block = rules_to_cil(rules)

    # Check each line — skip any that are already present
    new_lines = []
    skipped = 0
    for line in cil_block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(';'):
            if stripped in existing:
                skipped += 1
                continue
        new_lines.append(line)

    if skipped:
        print(f"  [~] Skipped {skipped} CIL statement(s) already present")

    additions = [l for l in new_lines if l.strip() and not l.strip().startswith(';')]
    if not additions:
        print("  [~] No new CIL statements to add")
        return True

    # Lay down the mods marker before the first modification if the file
    # doesn't already carry one.  Everything sepinject appends lands at EOF,
    # so a marker inserted here keeps all mods below it — which is what the
    # rest of the suite (SEPclean, SEPwalk --rebuild-neverallows) relies on.
    prefix_lines = []
    if MODS_MARKER_SUBSTR not in existing:
        print(f"  [+] No mods marker found — inserting "
              f"{REBUILD_MODS_MARKER_DEFAULT!r} before first modification "
              f"(delimits the sepinject-managed region for SEPclean/SEPwalk)")
        prefix_lines = ['', REBUILD_MODS_MARKER_DEFAULT, '']

    # Ensure the append starts on its own line even if the existing file did
    # not end in a newline, so the marker/first statement can't fuse onto a
    # trailing stock line.
    lead = '' if existing.endswith('\n') or not existing else '\n'

    with open(cil_path, 'a') as f:
        f.write(lead + '\n'.join(prefix_lines + new_lines))

    print(f"  [+] Added {len(additions)} CIL statement(s)")
    return True


# ---------------------------------------------------------------------------
# SHA-256 recomputation
# ---------------------------------------------------------------------------

def _api_version_from_vers_file(selinux_dir: Path) -> Optional[str]:
    """
    Read plat_sepolicy_vers.txt from the vendor selinux dir to find the
    vendor API freeze version, then return the CURRENT platform API level
    by finding the highest non-compat mapping CIL in selinux_dir/mapping/.
    init hashes: <policy>.cil + mapping/<MAX_API>.cil  (single file, not all).
    """
    mapping_dir = selinux_dir / 'mapping'
    if not mapping_dir.is_dir():
        return None
    # Find the highest versioned non-compat mapping CIL, e.g. 34.0.cil
    import re as _re
    candidates = []
    for f in mapping_dir.glob('*.cil'):
        m = _re.match(r'(\d+)\.0\.cil$', f.name)
        if m:
            candidates.append((int(m.group(1)), f))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1].name  # e.g. "34.0.cil"


def compute_plat_hash(selinux_dir: Path, policy_cil_name: str = 'plat_sepolicy.cil') -> str:
    """
    Compute SHA-256 matching AOSP's build system and init:
      SHA256(<policy>.cil || mapping/<MAX_API>.cil)

    Only the single highest non-compat versioned mapping file is included,
    NOT all mapping/*.cil files.  This matches what the build system writes
    and what init verifies at runtime.
    """
    h = hashlib.sha256()
    policy_cil = selinux_dir / policy_cil_name
    h.update(policy_cil.read_bytes())

    mapping_file = _api_version_from_vers_file(selinux_dir)
    if mapping_file:
        mapping_path = selinux_dir / 'mapping' / mapping_file
        if mapping_path.exists():
            h.update(mapping_path.read_bytes())
            print(f"  [*] Hash covers: {policy_cil_name} + mapping/{mapping_file}")
        else:
            print(f"  [!] Mapping file not found: {mapping_path}")
    else:
        print(f"  [!] No versioned mapping CIL found in {selinux_dir}/mapping/")

    return h.hexdigest()



def update_sha256(selinux_dir: Path, vendor_selinux_dir: Optional[Path],
                  system_ext_selinux_dir: Optional[Path] = None) -> bool:
    """
    Recompute all policy SHA-256 sidecars that init verifies at boot:

      plat:
        system/etc/selinux/plat_sepolicy_and_mapping.sha256
        vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256

      system_ext (if present):
        system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256
        vendor/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256

    Hash algorithm (matching AOSP build system and init):
      SHA256(<policy>.cil || mapping/<MAX_API>.cil)
    Only the single highest non-compat versioned mapping file is used.
    """
    sha_file = selinux_dir / 'plat_sepolicy_and_mapping.sha256'
    if not sha_file.exists():
        print(f"  [!] SHA256 file not found, skipping: {sha_file}")
        return False

    print(f"\n[*] Recomputing SHA-256 sidecars")

    # ---- plat hash ----
    new_hash = compute_plat_hash(selinux_dir, 'plat_sepolicy.cil')
    old_hash = sha_file.read_text().strip()

    if new_hash == old_hash:
        print(f"  [~] Plat hash unchanged: {new_hash}")
    else:
        backup = sha_file.with_suffix('.sha256.bak')
        if not backup.exists():
            shutil.copy2(sha_file, backup)
        sha_file.write_text(new_hash + '\n')
        print(f"  [+] Plat hash:  {old_hash}")
        print(f"              ->  {new_hash}")

        if vendor_selinux_dir:
            sidecar = vendor_selinux_dir / 'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256'
            if sidecar.exists():
                old_v = sidecar.read_text().strip()
                bak_v = sidecar.with_suffix('.sha256.bak')
                if not bak_v.exists():
                    shutil.copy2(sidecar, bak_v)
                sidecar.write_text(new_hash + '\n')
                print(f"  [+] Vendor plat sidecar: {old_v} -> {new_hash}")
            else:
                print(f"  [~] Vendor plat sidecar not found: {sidecar}")

    # ---- system_ext hash ----
    if system_ext_selinux_dir and system_ext_selinux_dir.is_dir():
        sext_cil = system_ext_selinux_dir / 'system_ext_sepolicy.cil'
        sext_sha_file = system_ext_selinux_dir / 'system_ext_sepolicy_and_mapping.sha256'
        if sext_cil.exists() and sext_sha_file.exists():
            sext_hash = compute_plat_hash(system_ext_selinux_dir, 'system_ext_sepolicy.cil')
            old_sext = sext_sha_file.read_text().strip()
            if sext_hash == old_sext:
                print(f"  [~] system_ext hash unchanged: {sext_hash}")
            else:
                bak_s = sext_sha_file.with_suffix('.sha256.bak')
                if not bak_s.exists():
                    shutil.copy2(sext_sha_file, bak_s)
                sext_sha_file.write_text(sext_hash + '\n')
                print(f"  [+] system_ext hash: {old_sext} -> {sext_hash}")

                if vendor_selinux_dir:
                    sext_sidecar = vendor_selinux_dir / 'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256'
                    if sext_sidecar.exists():
                        old_sv = sext_sidecar.read_text().strip()
                        bak_sv = sext_sidecar.with_suffix('.sha256.bak')
                        if not bak_sv.exists():
                            shutil.copy2(sext_sidecar, bak_sv)
                        sext_sidecar.write_text(sext_hash + '\n')
                        print(f"  [+] Vendor system_ext sidecar: {old_sv} -> {sext_hash}")
                    else:
                        print(f"  [~] Vendor system_ext sidecar not found: {sext_sidecar}")
        else:
            print(f"  [~] system_ext CIL or sha256 file not found, skipping system_ext hash")

    return True



# ---------------------------------------------------------------------------
# plat_seapp_contexts patching
# ---------------------------------------------------------------------------

def patch_seapp_contexts(seapp_path: Path, seapp_entries: list[str]) -> bool:
    """
    Append new entries to plat_seapp_contexts, skipping any already present.
    Each entry is a raw line like:
      user=_app isPrivApp=true name=com.example.app domain=myapp type=app_data_file levelFrom=all
    """
    if not seapp_path.exists():
        print(f"  [!] seapp_contexts not found, skipping: {seapp_path}")
        return False

    print(f"\n[*] Patching seapp_contexts: {seapp_path}")

    existing = seapp_path.read_text()
    existing_lines = {l.strip() for l in existing.splitlines()}

    to_add = []
    for entry in seapp_entries:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry in existing_lines:
            print(f"  [~] Already present: {entry}")
        else:
            to_add.append(entry)

    if not to_add:
        print("  [~] No new seapp_contexts entries to add")
        return True

    backup = seapp_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(seapp_path, backup)
        print(f"  [+] Backup: {backup}")

    with open(seapp_path, 'a') as f:
        f.write('\n')
        for entry in to_add:
            f.write(entry + '\n')

    print(f"  [+] Added {len(to_add)} seapp_contexts entry/entries:")
    for e in to_add:
        print(f"      {e}")

    return True


def remove_seapp_contexts(seapp_path: Path, entries_to_remove: list[str]) -> bool:
    """
    Remove specific entries from plat_seapp_contexts by exact line match.
    Used to remove stale entries before adding replacement ones.
    """
    if not seapp_path.exists():
        print(f"  [!] seapp_contexts not found, skipping: {seapp_path}")
        return False

    print(f"\n[*] Removing seapp_contexts entries from: {seapp_path}")

    remove_set = {e.strip() for e in entries_to_remove if e.strip() and not e.strip().startswith('#')}
    original_lines = seapp_path.read_text().splitlines(keepends=True)

    kept = []
    removed = 0
    for line in original_lines:
        if line.strip() in remove_set:
            print(f"  [-] Removed: {line.strip()}")
            removed += 1
        else:
            kept.append(line)

    if removed == 0:
        print("  [~] No matching seapp_contexts entries found to remove")
        return True

    backup = seapp_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(seapp_path, backup)
        print(f"  [+] Backup: {backup}")

    seapp_path.write_text(''.join(kept))
    print(f"  [+] Removed {removed} seapp_contexts entry/entries")
    return True


def parse_seapp_file(path: str) -> list[str]:
    """Read a seapp_contexts snippet file — one entry per line, # comments allowed."""
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# plat_file_contexts patching
# ---------------------------------------------------------------------------

def patch_file_contexts(file_ctx_path: Path, file_ctx_entries: list[str]) -> bool:
    """
    Append new entries to plat_file_contexts, skipping any already present.
    Each entry is a raw line like:
      /system/bin/mybin    u:object_r:mybin_exec:s0
    """
    if not file_ctx_path.exists():
        print(f"  [!] file_contexts not found, skipping: {file_ctx_path}")
        return False

    print(f"\n[*] Patching file_contexts: {file_ctx_path}")

    existing = file_ctx_path.read_text()
    existing_lines = {l.strip() for l in existing.splitlines()}

    to_add = []
    for entry in file_ctx_entries:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry in existing_lines:
            print(f"  [~] Already present: {entry}")
        else:
            to_add.append(entry)

    if not to_add:
        print("  [~] No new file_contexts entries to add")
        return True

    backup = file_ctx_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(file_ctx_path, backup)
        print(f"  [+] Backup: {backup}")

    with open(file_ctx_path, 'a') as f:
        f.write('\n')
        for entry in to_add:
            f.write(entry + '\n')

    print(f"  [+] Added {len(to_add)} file_contexts entry/entries:")
    for e in to_add:
        print(f"      {e}")

    return True


def parse_file_contexts_file(path: str) -> list[str]:
    """Read a file_contexts snippet file — one entry per line, # comments allowed."""
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# property_contexts patching
# Labels Android system properties so SELinux can control read/write access.
#
# Format (one entry per line):
#   persist.keyboard.ime_set    u:object_r:exported_default_prop:s0 exact bool
#   persist.vendor.             u:object_r:vendor_default_prop:s0
#
# The file lives at:  system/fs_tree/system/etc/selinux/plat_property_contexts
# Vendor properties: vendor/fs_tree/etc/selinux/vendor_property_contexts
#
# Common property context types used in AOSP:
#   exported_default_prop      — readable by all apps via SystemProperties
#   exported_system_prop       — readable by all, settable only by system
#   exported2_default_prop     — readable by all; legacy name
#   system_prop                — system partition only
#   vendor_default_prop        — vendor partition properties
#   bluetooth_prop             — Bluetooth HAL properties
#   radio_prop                 — RIL/telephony properties
#   wifi_prop                  — Wi-Fi HAL properties
#   log_prop                   — logging control properties
#   debug_prop                 — debug/userdebug properties
#   persist_debug_prop         — persist debug properties
# ---------------------------------------------------------------------------

def patch_property_contexts(prop_ctx_path: Path, entries: list[str]) -> bool:
    """Append new entries to a property_contexts file, skipping duplicates."""
    if not prop_ctx_path.exists():
        print(f"  [!] property_contexts not found, skipping: {prop_ctx_path}")
        return False

    print(f"\n[*] Patching property_contexts: {prop_ctx_path}")

    existing = prop_ctx_path.read_text()
    existing_lines = {l.strip() for l in existing.splitlines()}

    to_add = []
    for entry in entries:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry in existing_lines:
            print(f"  [~] Already present: {entry}")
        else:
            to_add.append(entry)

    if not to_add:
        print("  [~] No new property_contexts entries to add")
        return True

    backup = prop_ctx_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(prop_ctx_path, backup)
        print(f"  [+] Backup: {backup}")

    with open(prop_ctx_path, 'a') as f:
        f.write('\n')
        for entry in to_add:
            f.write(entry + '\n')

    print(f"  [+] Added {len(to_add)} property_contexts entry/entries:")
    for e in to_add:
        print(f"      {e}")

    return True


def parse_property_contexts_file(path: str) -> list[str]:
    """Read a property_contexts snippet — one entry per line, # comments allowed."""
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# service_contexts patching
# Labels Binder services registered in ServiceManager.
# Controls which domains can call (find/add/list) each named service.
#
# Format:
#   settings                    u:object_r:settings_service:s0
#   activity                    u:object_r:activity_service:s0
#
# File: system/fs_tree/system/etc/selinux/plat_service_contexts
#
# When you see AVC: denied { find } for sclass=service_manager
# you need either a new entry here or an allow rule for the existing label.
# ---------------------------------------------------------------------------

def patch_service_contexts(svc_ctx_path: Path, entries: list[str]) -> bool:
    """Append new entries to plat_service_contexts, skipping duplicates."""
    if not svc_ctx_path.exists():
        print(f"  [!] service_contexts not found, skipping: {svc_ctx_path}")
        return False

    print(f"\n[*] Patching service_contexts: {svc_ctx_path}")

    existing = svc_ctx_path.read_text()
    existing_lines = {l.strip() for l in existing.splitlines()}

    to_add = []
    for entry in entries:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry in existing_lines:
            print(f"  [~] Already present: {entry}")
        else:
            to_add.append(entry)

    if not to_add:
        print("  [~] No new service_contexts entries to add")
        return True

    backup = svc_ctx_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(svc_ctx_path, backup)
        print(f"  [+] Backup: {backup}")

    with open(svc_ctx_path, 'a') as f:
        f.write('\n')
        for entry in to_add:
            f.write(entry + '\n')

    print(f"  [+] Added {len(to_add)} service_contexts entry/entries:")
    for e in to_add:
        print(f"      {e}")

    return True


def parse_service_contexts_file(path: str) -> list[str]:
    """Read a service_contexts snippet — one entry per line, # comments allowed."""
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# hwservice_contexts patching
# Labels HIDL (Hardware Interface Definition Language) services.
# Controls which domains can access hardware services via hwservicemanager.
#
# Format:
#   android.hardware.light@2.0::ILight/default    u:object_r:hal_light_hwservice:s0
#   vendor.foo.bar@1.0::IBar/default              u:object_r:vendor_bar_hwservice:s0
#
# File: vendor/fs_tree/etc/selinux/vendor_hwservice_contexts
#       (or system/fs_tree/system/etc/selinux/plat_hwservice_contexts for AOSP HALs)
#
# When you see AVC: denied { find } for sclass=hwservice_manager
# you need either a new entry here or an allow rule for the existing label.
# ---------------------------------------------------------------------------

def patch_hwservice_contexts(hwsvc_ctx_path: Path, entries: list[str]) -> bool:
    """Append new entries to hwservice_contexts, skipping duplicates."""
    if not hwsvc_ctx_path.exists():
        print(f"  [!] hwservice_contexts not found, skipping: {hwsvc_ctx_path}")
        return False

    print(f"\n[*] Patching hwservice_contexts: {hwsvc_ctx_path}")

    existing = hwsvc_ctx_path.read_text()
    existing_lines = {l.strip() for l in existing.splitlines()}

    to_add = []
    for entry in entries:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry in existing_lines:
            print(f"  [~] Already present: {entry}")
        else:
            to_add.append(entry)

    if not to_add:
        print("  [~] No new hwservice_contexts entries to add")
        return True

    backup = hwsvc_ctx_path.with_suffix('.bak')
    if not backup.exists():
        shutil.copy2(hwsvc_ctx_path, backup)
        print(f"  [+] Backup: {backup}")

    with open(hwsvc_ctx_path, 'a') as f:
        f.write('\n')
        for entry in to_add:
            f.write(entry + '\n')

    print(f"  [+] Added {len(to_add)} hwservice_contexts entry/entries:")
    for e in to_add:
        print(f"      {e}")

    return True


def parse_hwservice_contexts_file(path: str) -> list[str]:
    """Read a hwservice_contexts snippet — one entry per line, # comments allowed."""
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# ROM root auto-discovery
# ---------------------------------------------------------------------------

# Binary sepolicy locations (relative to rom_root)
ROM_POLICY_CANDIDATES = [
    'vendor_boot/cpio_tree/sepolicy',
    'vendor/fs_tree/etc/selinux/precompiled_sepolicy',
    'system/fs_tree/system/etc/selinux/precompiled_sepolicy',
]

# system/etc/selinux directory (CIL source + seapp + file_contexts + sha256)
ROM_SYSTEM_SELINUX = 'system/fs_tree/system/etc/selinux'

# system_ext/etc/selinux directory (system_ext CIL + sha256)
# Note: only the `system` partition has the extra `system/` between fs_tree
# and etc/ (because /system gets mounted at /system, and the dump includes
# the inner mount path). system_ext is dumped as its own root, so the path
# is just system_ext/fs_tree/etc/selinux — no extra system_ext/ in between.
ROM_SYSTEM_EXT_SELINUX = 'system_ext/fs_tree/etc/selinux'

# vendor/etc/selinux directory (vendor sidecar sha256 + hwservice_contexts)
ROM_VENDOR_SELINUX = 'vendor/fs_tree/etc/selinux'

# Filenames within selinux dirs
PLAT_PROPERTY_CONTEXTS  = 'plat_property_contexts'
PLAT_SERVICE_CONTEXTS   = 'plat_service_contexts'
PLAT_HWSERVICE_CONTEXTS = 'plat_hwservice_contexts'
VENDOR_PROPERTY_CONTEXTS  = 'vendor_property_contexts'
VENDOR_HWSERVICE_CONTEXTS = 'vendor_hwservice_contexts'


def is_mls_policy(policy_path: Path) -> bool:
    """
    Return True if the binary policy file has the MLS flag set.
    The policydb header has a "mls" field at a fixed offset — the
    simplest reliable check is to let libsepol report it via `file`.
    """
    try:
        r = subprocess.run(
            ['file', str(policy_path)],
            capture_output=True, text=True
        )
        return ' MLS ' in r.stdout
    except Exception:
        return False  # assume non-MLS if we cannot check


def find_policies_in_rom(rom_root: Path) -> list[Path]:
    found = []
    for rel in ROM_POLICY_CANDIDATES:
        p = rom_root / rel
        if not p.exists():
            print(f"  [~] Binary policy not found (skipping): {p}")
            continue
        # vendor_boot/sepolicy must stay non-MLS — the kernel loads it at
        # first-stage init and will reject an MLS binary.  The C helper's
        # policydb_to_image always serialises with MLS enabled, so patching
        # a non-MLS binary corrupts it.  Skip it here; the CIL patch and
        # the vendor/precompiled_sepolicy binary patch cover all needed rules.
        if not is_mls_policy(p):
            print(f"  [~] Skipping non-MLS binary (first-stage policy, CIL covers this): {p}")
            continue
        found.append(p)
    return found


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Inject SELinux policy rules from a .te file into Android ROM policy files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input rules
    parser.add_argument('--te', metavar='RULES.te',
                        help='.te file with SELinux policy rules to ADD '
                             '(allow, type, genfscon, typeattribute, ...)')
    parser.add_argument('--remove-te', metavar='REMOVE.te',
                        help='.te file with rules to REMOVE from the policy. '
                             'Same syntax as --te but each statement is prefixed '
                             'with remove_: remove_allow, remove_type, '
                             'remove_genfscon, remove_permissive, remove_typeattribute')
    parser.add_argument('--seapp', metavar='SEAPP.txt',
                        help='File with seapp_contexts lines to append to plat_seapp_contexts')
    parser.add_argument('--remove-seapp', metavar='REMOVE_SEAPP.txt',
                        help='File with seapp_contexts lines to REMOVE from plat_seapp_contexts '
                             '(exact line match). Run before --seapp to replace stale entries.')
    parser.add_argument('--file-contexts', metavar='FILE_CTX.txt',
                        help='File with file_contexts lines to append to plat_file_contexts')
    parser.add_argument('--property-contexts', metavar='PROP_CTX.txt',
                        help='File with property_contexts lines to append to '
                             'plat_property_contexts (system) and/or vendor_property_contexts. '
                             'Format: "persist.foo.bar  u:object_r:mytype:s0 exact string"')
    parser.add_argument('--service-contexts', metavar='SVC_CTX.txt',
                        help='File with service_contexts lines to append to '
                             'plat_service_contexts. '
                             'Format: "my.service.name  u:object_r:my_service:s0"')
    parser.add_argument('--hwservice-contexts', metavar='HWSVC_CTX.txt',
                        help='File with hwservice_contexts lines to append to '
                             'plat_hwservice_contexts or vendor_hwservice_contexts. '
                             'Format: "vendor.foo@1.0::IFoo/default  u:object_r:hal_foo_hwservice:s0"')

    # Targets — explicit paths
    parser.add_argument('--policy', nargs='+', metavar='POLICY_FILE',
                        help='One or more binary sepolicy files to patch directly')
    parser.add_argument('--system-selinux', metavar='DIR',
                        help='Path to system/etc/selinux directory '
                             '(for CIL, seapp_contexts, file_contexts, sha256 update)')
    parser.add_argument('--vendor-selinux', metavar='DIR',
                        help='Path to vendor/etc/selinux directory '
                             '(for vendor sidecar sha256 update)')

    # Targets — ROM root auto-discovery
    parser.add_argument('--rom-root', metavar='DIR',
                        help='Root of an unpacked ROM; auto-discovers all targets')

    # Misc
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without writing any files')
    parser.add_argument('--dump-json', metavar='OUT.json',
                        help='Write parsed binary-patch rules to a JSON file')
    parser.add_argument('--skip-binary', action='store_true',
                        help='Skip binary sepolicy patching (CIL/context only)')
    parser.add_argument('--skip-cil', action='store_true',
                        help='Skip plat_sepolicy.cil patching')
    parser.add_argument('--skip-seapp', action='store_true',
                        help='Skip plat_seapp_contexts patching')
    parser.add_argument('--skip-file-contexts', action='store_true',
                        help='Skip plat_file_contexts patching')
    parser.add_argument('--skip-property-contexts', action='store_true',
                        help='Skip property_contexts patching')
    parser.add_argument('--skip-service-contexts', action='store_true',
                        help='Skip service_contexts patching')
    parser.add_argument('--skip-hwservice-contexts', action='store_true',
                        help='Skip hwservice_contexts patching')
    parser.add_argument('--skip-sha256', action='store_true',
                        help='Skip SHA-256 recomputation')
    parser.add_argument('--skip-neverallow-check', action='store_true',
                        help='Skip the pre-flight CIL neverallow conflict scan. '
                             'By default, the tool checks whether any --te allow '
                             'rules conflict with existing CIL neverallow rules '
                             'and offers to rewrite them.')
    parser.add_argument('--plat-cil-only', action='store_true',
                        help='When running the neverallow conflict scan, only '
                             'process plat_sepolicy.cil (the system partition '
                             'CIL). By default the scan also covers '
                             'vendor_sepolicy.cil and system_ext_sepolicy.cil '
                             'where present, matching the scope of binary '
                             'policy patching.')

    # ---- Multi-CIL extensions (added to handle new-domain compile failures) ----
    parser.add_argument('--no-auto-coredomain', action='store_true',
                        help='Disable automatic coredomain attribution for new '
                             'domains. By default, any type declared as a domain '
                             '(or targeted by a process-class type_transition) is '
                             'automatically added to the coredomain typeattributeset '
                             'in plat_sepolicy.cil. This is required to satisfy '
                             'Treble plat-vs-vendor neverallows for new plat-side '
                             'domains. Disable only if you know what you are doing.')
    parser.add_argument('--coredomain', metavar='TYPE', action='append', default=[],
                        help='Explicitly add this type name to the coredomain '
                             'typeattributeset in plat_sepolicy.cil. Can be passed '
                             'multiple times. Useful when --no-auto-coredomain is '
                             'set, or when you want to add a type to coredomain '
                             'without declaring it via --te.')
    parser.add_argument('--vendor-attr-add', metavar='ATTR=TYPE1,TYPE2', action='append',
                        default=[],
                        help='Augment a typeattributeset in vendor_sepolicy.cil. '
                             'Format: --vendor-attr-add ATTR=TYPE1,TYPE2. The '
                             'specified types are added to the named attribute set '
                             "in vendor's CIL without re-declaring the types "
                             '(which would cause a duplicate-declaration compile '
                             'error). Use this when a new plat-side type needs '
                             'membership in a vendor-defined attribute set.')

    # ---- Validate-only flags ----
    parser.add_argument('--validate', action='store_true',
                        help='Run policy validation in surgical mode: scan '
                             'all CIL files under --rom-root for broken '
                             'sepinject artifacts (nested aux refs, dangling '
                             'aux references, orphaned/empty/duplicate aux '
                             'decls, unrecoverable blocks) and offer to '
                             'repair each one by rebuilding from the audit-'
                             'trail baseline.  Standalone mode only — must '
                             'be combined with --rom-root; combinable with '
                             '--dry-run for a no-op preview.  Backs up '
                             'every touched CIL file to '
                             '<rom-root>/sepinject_validate_backup_<TS>/ '
                             'before making any change (skipped under '
                             '--dry-run).')
    parser.add_argument('--validate-full', action='store_true',
                        help='Like --validate, but rebuild EVERY sepinject '
                             'rewrite block in every targeted CIL file '
                             'from baseline — even ones that currently '
                             'look well-formed.  Use this when the policy '
                             'is badly corrupted and a from-scratch rebuild '
                             'is preferable to per-issue surgery.  Implies '
                             '--validate.')

    # ---- Rebuild-neverallows (recovery) flag ----
    parser.add_argument('--rebuild-neverallows', action='store_true',
                        help='Recovery mode: scan the same fixed set of '
                             'CIL files the normal pre-flight check '
                             'already targets under --rom-root '
                             '(plat_sepolicy.cil, system_ext_sepolicy.cil, '
                             'vendor_sepolicy.cil, and plat_pub_versioned.cil '
                             '— NOT a recursive glob), look for the marker '
                             'line '
                             f'{REBUILD_MODS_MARKER_DEFAULT!r}, extract '
                             'every `(allow ...)` rule below the marker, '
                             'and re-run the pre-flight neverallow conflict '
                             'check against the FULL set of neverallows in '
                             'those CIL files.  Conflicts are rewritten via '
                             'the same carve-out / perm-drop machinery used '
                             'by the normal patch flow.  Standalone — '
                             'requires --rom-root, accepts --dry-run / '
                             '--skip-sha256 / --plat-cil-only / --yes.  '
                             'Backs up every targeted CIL into '
                             '<rom-root>/sepinject_rebuild_neverallows_backup_<TS>/'
                             ' before any write.  Assumes the user has '
                             'already manually removed prior sepinject_aux_* '
                             'rewrites and restored the original commented '
                             'neverallow lines as live statements.')
    parser.add_argument('--rebuild-mods-marker', metavar='MARKER',
                        default=REBUILD_MODS_MARKER_DEFAULT,
                        help='Override the marker line used by '
                             '--rebuild-neverallows to find the start of '
                             f'user mods (default: {REBUILD_MODS_MARKER_DEFAULT!r})')
    parser.add_argument('--yes', '--assume-yes', dest='assume_yes',
                        action='store_true',
                        help='Auto-approve the interactive prompt issued by '
                             '--rebuild-neverallows / --recreate-mlsconstrains '
                             '(and the --check-mlsconstrains pre-flight).  Use '
                             'with care — in recovery scenarios you may want to '
                             'review each rewrite first.')

    # ---- Recreate-mlsconstrains (recovery) flag ----
    parser.add_argument('--recreate-mlsconstrains', action='store_true',
                        help='Recovery mode, the MLS analogue of '
                             '--rebuild-neverallows: scan the same fixed set '
                             'of CIL files under --rom-root (plat_sepolicy.cil, '
                             'system_ext_sepolicy.cil, vendor_sepolicy.cil, '
                             'plat_pub_versioned.cil — NOT a recursive glob), '
                             f'look for the marker line {REBUILD_MODS_MARKER_DEFAULT!r}, '
                             'extract every `(allow ...)` below it, and check '
                             'those against the FULL set of mlsconstrains.  A '
                             'constraint that would (or could) DENY a mod allow '
                             'at runtime is widened with an '
                             '`(or ORIG (eq t1 sepinject_mlsaux_*))` exemption '
                             'for the offending subject domain(s).  Standalone — '
                             'requires --rom-root, accepts --dry-run / '
                             '--skip-sha256 / --plat-cil-only / --yes and the '
                             'shared --rebuild-mods-marker.  Backs up every '
                             'targeted CIL into '
                             '<rom-root>/sepinject_recreate_mlsconstrains_backup_<TS>/'
                             ' before any write.')

    parser.add_argument('--recreate-mls-domain', metavar='DOMAIN', default=None,
                        help='Like --recreate-mlsconstrains, but only widen '
                             'constraints that block the single source domain '
                             'DOMAIN — the mod allow rules are filtered to '
                             'rule.src == DOMAIN before the scan.  Use this to '
                             'exempt one domain at a time instead of punching '
                             'holes in every constraint for every mod subject '
                             'at once.  Same standalone requirements/flags as '
                             '--recreate-mlsconstrains.')

    # ---- Inline mlsconstrain pre-flight (opt-in) ----
    parser.add_argument('--check-mlsconstrains', action='store_true',
                        help='During a normal --te patch run, ALSO scan for '
                             'mlsconstrain conflicts (constraints that would '
                             'deny an injected allow at runtime) and offer to '
                             'widen them, mirroring the neverallow pre-flight.  '
                             'This is OPT-IN (the neverallow pre-flight is '
                             'opt-out) on purpose: unlike neverallow conflicts, '
                             'mlsconstrain conflicts do NOT break a CIL '
                             'recompile, so auto-relaxing MLS on every run '
                             'would silently loosen policy.  Enable it only '
                             'when you specifically want MLS constraints '
                             'considered.')

    args = parser.parse_args()

    # ---- Validate-only path (standalone) ----
    # --validate / --validate-full are explicit, never auto-run, and must
    # be paired with --rom-root.  They short-circuit the normal patch
    # flow and exit when done.  Combinable with --dry-run for a no-op
    # preview.
    if args.validate or args.validate_full:
        if not args.rom_root:
            parser.error("--validate requires --rom-root")
        if args.te or args.remove_te or args.seapp or args.remove_seapp \
                or args.file_contexts or args.property_contexts \
                or args.service_contexts or args.hwservice_contexts:
            parser.error("--validate is standalone — do not combine with "
                         "--te / --seapp / --*-contexts flags")
        rr = Path(args.rom_root)
        if not rr.exists() or not rr.is_dir():
            parser.error(f"--rom-root path does not exist or is not a "
                         f"directory: {rr}")
        # Resolve targeted CIL files under rom_root.
        v_cils: list = []
        sys_sel = rr / ROM_SYSTEM_SELINUX
        if sys_sel.exists():
            plat = sys_sel / 'plat_sepolicy.cil'
            if plat.exists():
                v_cils.append(('plat', plat))
        sext_sel = rr / ROM_SYSTEM_EXT_SELINUX
        if sext_sel.exists():
            sext = sext_sel / 'system_ext_sepolicy.cil'
            if sext.exists():
                v_cils.append(('system_ext', sext))
        vnd_sel = rr / ROM_VENDOR_SELINUX
        if vnd_sel.exists():
            vnd = vnd_sel / 'vendor_sepolicy.cil'
            if vnd.exists():
                v_cils.append(('vendor', vnd))
        if not v_cils:
            print(f"[!] No CIL files found under {rr}.  Nothing to validate.")
            sys.exit(1)
        code = validate_policy(
            rom_root=rr,
            cil_paths=v_cils,
            full_rebuild=args.validate_full,
            dry_run=args.dry_run,
        )
        sys.exit(code)

    # ---- Rebuild-neverallows path (standalone) ----
    # --rebuild-neverallows is explicit, never auto-run, and must be
    # paired with --rom-root.  It short-circuits the normal patch flow
    # and exits when done.  Combinable with --dry-run / --skip-sha256 /
    # --plat-cil-only / --yes.  Incompatible with rule-injection flags
    # since the "rules" come from the user's existing CIL modifications.
    if args.rebuild_neverallows:
        if not args.rom_root:
            parser.error("--rebuild-neverallows requires --rom-root")
        if (args.te or args.remove_te or args.seapp or args.remove_seapp
                or args.file_contexts or args.property_contexts
                or args.service_contexts or args.hwservice_contexts
                or args.validate or args.validate_full):
            parser.error("--rebuild-neverallows is standalone — do not "
                         "combine with --te / --remove-te / --seapp / "
                         "--*-contexts / --validate flags")
        rr = Path(args.rom_root)
        if not rr.exists() or not rr.is_dir():
            parser.error(f"--rom-root path does not exist or is not a "
                         f"directory: {rr}")
        code = rebuild_neverallows(
            rom_root=rr,
            dry_run=args.dry_run,
            skip_sha256=args.skip_sha256,
            plat_only=args.plat_cil_only,
            assume_yes=args.assume_yes,
            marker=args.rebuild_mods_marker,
        )
        sys.exit(code)

    # ---- Recreate-mlsconstrains path (standalone) ----
    # The MLS analogue of --rebuild-neverallows: explicit, never auto-run,
    # must be paired with --rom-root.  Short-circuits the normal patch flow.
    # Combinable with --dry-run / --skip-sha256 / --plat-cil-only / --yes.
    # Incompatible with rule-injection and the other standalone modes.
    if args.recreate_mlsconstrains or args.recreate_mls_domain:
        if not args.rom_root:
            parser.error("--recreate-mlsconstrains requires --rom-root")
        if (args.te or args.remove_te or args.seapp or args.remove_seapp
                or args.file_contexts or args.property_contexts
                or args.service_contexts or args.hwservice_contexts
                or args.validate or args.validate_full
                or args.rebuild_neverallows):
            parser.error("--recreate-mlsconstrains is standalone — do not "
                         "combine with --te / --remove-te / --seapp / "
                         "--*-contexts / --validate / --rebuild-neverallows "
                         "flags")
        rr = Path(args.rom_root)
        if not rr.exists() or not rr.is_dir():
            parser.error(f"--rom-root path does not exist or is not a "
                         f"directory: {rr}")
        code = recreate_mlsconstrains(
            rom_root=rr,
            dry_run=args.dry_run,
            skip_sha256=args.skip_sha256,
            plat_only=args.plat_cil_only,
            assume_yes=args.assume_yes,
            marker=args.rebuild_mods_marker,
            only_domain=args.recreate_mls_domain,
        )
        sys.exit(code)

    has_target = args.policy or args.rom_root or args.system_selinux
    has_input = (args.te or args.remove_te or args.seapp or args.remove_seapp
                 or args.file_contexts or args.property_contexts
                 or args.service_contexts or args.hwservice_contexts)
    if not args.dry_run and not has_target:
        parser.error("Provide --rom-root, --policy, or --system-selinux (or use --dry-run)")
    # --rom-root alone is sufficient: binary sync and init-dir
    # file_contexts auto-injection run without any rule input files.
    if not has_input and not args.rom_root:
        parser.error("Provide at least one of: --te, --remove-te, --seapp, --file-contexts")

    # ---- Parse --te (add rules) ----
    rules: list[TeRule] = []
    if args.te:
        print(f"[*] Parsing add rules: {args.te}")
        rules = parse_te_file(args.te)
        print(f"[*] Parsed {len(rules)} add rule(s)")
    else:
        print("[~] No --te file provided — skipping rule injection")

    # ---- Parse --remove-te (remove rules) ----
    remove_rules: list[RemoveRule] = []
    if args.remove_te:
        print(f"[*] Parsing remove rules: {args.remove_te}")
        remove_rules = parse_remove_te_file(args.remove_te)
        print(f"[*] Parsed {len(remove_rules)} remove rule(s)")

    if not rules and not remove_rules:
        # Zero rules is fine if we are only patching context files
        # --rom-root alone is valid: binary sync and init-dir file_contexts
        # auto-injection will still run even with no rule or context files.
        has_context_work = (args.seapp or args.file_contexts or
                            args.property_contexts or args.service_contexts or
                            args.hwservice_contexts or args.rom_root)
        if not has_context_work:
            print("[!] No rules parsed and no context files provided.")
            print("    Nothing to do. Check your .te / --remove-te file.")
            sys.exit(1)
        print("[~] No policy rules to apply — proceeding with context file patches only.")

    rules_json = rules_to_json(rules) if rules else '[]'
    remove_json = remove_rules_to_json(remove_rules) if remove_rules else '[]'

    if args.dump_json:
        Path(args.dump_json).write_text(rules_json)
        print(f"[*] Rules JSON written to: {args.dump_json}")

    # ---- Parse optional context snippet files ----
    seapp_entries: list[str] = []
    if args.seapp:
        seapp_entries = parse_seapp_file(args.seapp)
        print(f"[*] Loaded {len(seapp_entries)} seapp_contexts entries from {args.seapp}")

    seapp_remove_entries: list[str] = []
    if args.remove_seapp:
        seapp_remove_entries = parse_seapp_file(args.remove_seapp)
        print(f"[*] Loaded {len(seapp_remove_entries)} seapp_contexts entries to remove from {args.remove_seapp}")

    file_ctx_entries: list[str] = []
    if args.file_contexts:
        file_ctx_entries = parse_file_contexts_file(args.file_contexts)
        print(f"[*] Loaded {len(file_ctx_entries)} file_contexts entries from {args.file_contexts}")

    prop_ctx_entries: list[str] = []
    if args.property_contexts:
        prop_ctx_entries = parse_property_contexts_file(args.property_contexts)
        print(f"[*] Loaded {len(prop_ctx_entries)} property_contexts entries from {args.property_contexts}")

    svc_ctx_entries: list[str] = []
    if args.service_contexts:
        svc_ctx_entries = parse_service_contexts_file(args.service_contexts)
        print(f"[*] Loaded {len(svc_ctx_entries)} service_contexts entries from {args.service_contexts}")

    hwsvc_ctx_entries: list[str] = []
    if args.hwservice_contexts:
        hwsvc_ctx_entries = parse_hwservice_contexts_file(args.hwservice_contexts)
        print(f"[*] Loaded {len(hwsvc_ctx_entries)} hwservice_contexts entries from {args.hwservice_contexts}")

    # ---- Dry run ----
    if args.dry_run:
        print("\n[*] Dry-run mode — nothing will be written.\n")

        if rules:
            print("--- Rules to ADD ---")
            for r in rules:
                if r.op in ('allow', 'auditallow', 'dontaudit'):
                    print(f"  {r.op} {r.src} {r.tgt}:{r.cls} {{ {' '.join(r.perms)} }};")
                elif r.op == 'permissive':
                    print(f"  permissive {r.type_name};")
                elif r.op in ('type', 'attribute'):
                    line = f"  {r.op} {r.type_name}"
                    if r.attr: line += f", {r.attr}"
                    print(line + ";")
                elif r.op == 'typeattribute':
                    print(f"  typeattribute {r.type_name} {r.attr};")
                elif r.op == 'type_transition':
                    print(f"  type_transition {r.src} {r.tgt}:{r.cls} {r.default};")
                elif r.op == 'genfscon':
                    print(f"  genfscon {r.fs_type} \"{r.path}\" {r.context};")

            print("\n--- CIL statements to add (plat_sepolicy.cil) ---")
            for line in rules_to_cil(rules).splitlines():
                if line.strip():
                    print(f"  {line}")

        if remove_rules:
            print("\n--- Rules to REMOVE ---")
            for r in remove_rules:
                if r.op == 'remove_allow':
                    print(f"  remove_allow {r.src} {r.tgt}:{r.cls} {{ {' '.join(r.perms)} }};")
                elif r.op == 'remove_genfscon':
                    print(f"  remove_genfscon {r.src} \"{r.tgt}\";")
                elif r.op == 'remove_permissive':
                    print(f"  remove_permissive {r.type_name};")
                elif r.op == 'remove_type':
                    print(f"  remove_type {r.type_name};  [CIL only]")
                elif r.op == 'remove_typeattribute':
                    print(f"  remove_typeattribute {r.type_name} {r.attr};")

        if seapp_entries:
            print("\n--- seapp_contexts entries (ADD) ---")
            for e in seapp_entries:
                print(f"  {e}")

        if seapp_remove_entries:
            print("\n--- seapp_contexts entries (REMOVE) ---")
            for e in seapp_remove_entries:
                print(f"  {e}")

        if file_ctx_entries:
            print("\n--- file_contexts entries ---")
            for e in file_ctx_entries:
                print(f"  {e}")

        if prop_ctx_entries:
            print("\n--- property_contexts entries ---")
            for e in prop_ctx_entries:
                print(f"  {e}")

        if svc_ctx_entries:
            print("\n--- service_contexts entries ---")
            for e in svc_ctx_entries:
                print(f"  {e}")

        if hwsvc_ctx_entries:
            print("\n--- hwservice_contexts entries ---")
            for e in hwsvc_ctx_entries:
                print(f"  {e}")

        # Dry-run preview of neverallow conflicts.
        # Resolve CIL paths just enough to scan; no files are modified.
        if rules and not args.skip_neverallow_check:
            print("\n--- Neverallow conflict preview (dry-run) ---")
            dr_rom_root = Path(args.rom_root) if args.rom_root else None
            dr_sys_selinux: Optional[Path] = None
            if args.system_selinux:
                dr_sys_selinux = Path(args.system_selinux)
            elif dr_rom_root:
                cand = dr_rom_root / ROM_SYSTEM_SELINUX
                if cand.is_dir():
                    dr_sys_selinux = cand
            dr_system_ext_selinux: Optional[Path] = None
            if dr_rom_root:
                cand = dr_rom_root / ROM_SYSTEM_EXT_SELINUX
                if cand.is_dir():
                    dr_system_ext_selinux = cand
            dr_vendor_selinux: Optional[Path] = None
            if args.vendor_selinux:
                dr_vendor_selinux = Path(args.vendor_selinux)
            elif dr_rom_root:
                cand = dr_rom_root / ROM_VENDOR_SELINUX
                if cand.is_dir():
                    dr_vendor_selinux = cand

            dr_cils: list = []
            if dr_sys_selinux:
                dr_cils.append(('plat', dr_sys_selinux / 'plat_sepolicy.cil'))
            if not args.plat_cil_only:
                if dr_vendor_selinux:
                    dr_cils.append(('vendor', dr_vendor_selinux / 'vendor_sepolicy.cil'))
                if dr_system_ext_selinux:
                    dr_cils.append(('system_ext',
                                    dr_system_ext_selinux / 'system_ext_sepolicy.cil'))

            if not dr_cils:
                print("  (no CIL files resolvable from given paths — skipping scan)")
            else:
                # find_neverallow_conflicts now returns (conflicts, attr_map,
                # all_types) — the latter two are unused in the dry-run
                # preview path; build_rewrite will fall back to using each
                # conflict's cached src_resolved field when its attr_map
                # argument is None, which is fine for cosmetic preview.
                dr_conflicts, _dr_attr_map, _dr_all_types = \
                    find_neverallow_conflicts(rules, dr_cils)
                if not dr_conflicts:
                    print("  [OK] No neverallow conflicts detected.")
                else:
                    print(f"  [!] {len(dr_conflicts)} conflict(s) would be detected:")
                    for i, c in enumerate(dr_conflicts, 1):
                        rule = c.rule
                        na = c.neverallow
                        print(f"\n  Conflict {i}:")
                        print(f"    Adding:    allow {rule.src} {rule.tgt}:"
                              f"{rule.cls} {{ {' '.join(rule.perms)} }};")
                        print(f"    Violates:  {na.raw_line.strip()}")
                        print(f"    Source:    {na.cil_path}:{na.line_no}")
                        print(f"    Matched:   perm(s) {{ {' '.join(c.matched_perms)} }}")
                        print(f"    Proposed:  {build_rewrite(c)}")
                    print("\n  In a non-dry run you'd be prompted to accept these rewrites.")

        return

    # ---- Resolve paths ----
    rom_root = Path(args.rom_root) if args.rom_root else None

    # Binary policy targets
    policies: list[Path] = []
    if not args.skip_binary:
        if args.policy:
            policies = [Path(p) for p in args.policy]
        if rom_root:
            policies.extend(find_policies_in_rom(rom_root))

    # system/etc/selinux dir
    sys_selinux: Optional[Path] = None
    if args.system_selinux:
        sys_selinux = Path(args.system_selinux)
    elif rom_root:
        candidate = rom_root / ROM_SYSTEM_SELINUX
        if candidate.is_dir():
            sys_selinux = candidate
        else:
            print(f"  [~] system selinux dir not found: {candidate}")

    # system_ext/etc/selinux dir
    system_ext_selinux: Optional[Path] = None
    if rom_root:
        candidate = rom_root / ROM_SYSTEM_EXT_SELINUX
        if candidate.is_dir():
            system_ext_selinux = candidate
        else:
            print(f"  [~] system_ext selinux dir not found (skipping): {candidate}")

    # vendor/etc/selinux dir
    vendor_selinux: Optional[Path] = None
    if args.vendor_selinux:
        vendor_selinux = Path(args.vendor_selinux)
    elif rom_root:
        candidate = rom_root / ROM_VENDOR_SELINUX
        if candidate.is_dir():
            vendor_selinux = candidate
        else:
            print(f"  [~] vendor selinux dir not found: {candidate}")

    # ---- Pre-flight: Neverallow conflict scan ----
    #
    # Before any patching begins, scan the CIL source files for `neverallow`
    # rules that would be violated by the requested `allow` rules.  At
    # runtime the kernel does not enforce neverallow (it's a compile-time
    # assertion), so the binary patches will work regardless.  But if `init`
    # ever has to recompile from CIL (which it does on SHA-256 mismatch),
    # `secilc` will refuse to build the policy and the device may fall back
    # to a clean state without the injected rules — or fail to boot.
    #
    # This check finds those conflicts up front and offers to rewrite the
    # offending neverallow rules.  See the neverallow_module section above
    # for the full strategy.
    rollback: Optional[RollbackSession] = None  # created lazily if needed
    neverallow_rewrites_ok: Optional[bool] = None
    mlsconstrain_rewrites_ok: Optional[bool] = None

    if rules and not args.skip_neverallow_check:
        print("\n[*] Pre-flight neverallow conflict scan")

        # Build the list of CIL files to scan.  Plat is always included if
        # available; vendor and system_ext are included unless --plat-cil-only.
        #
        # IMPORTANT: plat_pub_versioned.cil lives on the vendor partition but
        # contains a versioned copy of plat-side rules — including the same
        # `(neverallow domain ...)` style rules that appear in plat_sepolicy.cil.
        # When `init` recompiles from CIL it concatenates ALL CIL files, so
        # missing this one means a conflict that's been rewritten in plat
        # still trips its identical twin here and the recompile fails (boot loop).
        # The scanner historically didn't include this file; we add it now.
        cil_paths_to_scan: list = []
        if sys_selinux:
            cil_paths_to_scan.append(('plat', sys_selinux / 'plat_sepolicy.cil'))
        if not args.plat_cil_only:
            if vendor_selinux:
                cil_paths_to_scan.append(('vendor', vendor_selinux / 'vendor_sepolicy.cil'))
                # plat_pub_versioned.cil is on the vendor partition but contains
                # plat-side neverallows. Scan it for the same conflicts.
                ppv_path = vendor_selinux / 'plat_pub_versioned.cil'
                if ppv_path.exists():
                    cil_paths_to_scan.append(('plat_pub_versioned', ppv_path))
            if system_ext_selinux:
                cil_paths_to_scan.append(('system_ext',
                                          system_ext_selinux / 'system_ext_sepolicy.cil'))

        # Run the binary safety scan (read-only).  Surfaces unexpected
        # AVTAB_NEVERALLOW entries in any of the binaries the script would
        # patch.  Standard AOSP-built kernel binaries have zero — this is
        # purely a sanity check for non-standard vendor artifacts.
        binary_findings: list = []
        if policies:
            try:
                helper_for_scan = get_or_compile_helper()
                print(f"  [*] Scanning {len(policies)} binary policy/policies for "
                      f"unexpected neverallow entries")
                binary_findings = scan_binary_neverallows(helper_for_scan, policies)
            except Exception as e:
                print(f"  [~] Binary neverallow scan failed (continuing): {e}")

        # CIL conflict detection.  find_neverallow_conflicts now returns a
        # (conflicts, attr_map, all_types) tuple — attr_map and all_types
        # are threaded into apply_neverallow_rewrites so build_rewrite can
        # perform robust vacuity checks (Bug 1 fix: ensures we don't emit
        # an empty (and X (not Y)) carve-out when the resolved source set
        # of X is entirely contained in Y).
        conflicts: list = []
        na_attr_map: dict = {}
        na_all_types: set = set()
        if cil_paths_to_scan:
            conflicts, na_attr_map, na_all_types = \
                find_neverallow_conflicts(rules, cil_paths_to_scan)

        if conflicts or binary_findings:
            proceed = prompt_neverallow_conflicts(conflicts, binary_findings)
            if not proceed:
                print("\n[!] User declined neverallow rewrites.")
                print("[!] No files have been modified yet; exiting cleanly.")
                # No rollback was created; we haven't touched anything.
                sys.exit(2)

            # User said yes.  NOW create the rollback session — this is the
            # earliest point at which we'll actually modify any file.
            rollback = RollbackSession()
            print(f"\n[*] Rollback snapshot dir: {rollback.session_dir}")
            print("[*] User accepted; snapshotting files before modification")
            for _, cil_p in cil_paths_to_scan:
                if cil_p and cil_p.exists():
                    rollback.snapshot(cil_p)
            for pol in policies or []:
                rollback.snapshot(pol)
            # Also snapshot SHA-256 sidecars since they'll change
            if sys_selinux:
                rollback.snapshot(sys_selinux / 'plat_sepolicy_and_mapping.sha256')
            if vendor_selinux:
                rollback.snapshot(vendor_selinux /
                                  'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256')
            if system_ext_selinux:
                rollback.snapshot(system_ext_selinux /
                                  'system_ext_sepolicy_and_mapping.sha256')
                if vendor_selinux:
                    rollback.snapshot(vendor_selinux /
                                      'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256')

            # Apply the rewrites
            try:
                rewrite_results = apply_neverallow_rewrites(
                    conflicts, rollback,
                    all_cil_paths=cil_paths_to_scan,
                    attr_map=na_attr_map,
                    all_types=na_all_types,
                )
                neverallow_rewrites_ok = all(rewrite_results.values()) if rewrite_results else True
            except Exception as e:
                print(f"\n[!] Neverallow rewrite failed: {e}")
                rollback.revert()
                sys.exit(1)
        else:
            print("  [OK] No neverallow conflicts detected")
            neverallow_rewrites_ok = None  # no work needed

    # ---- Pre-flight: mlsconstrain conflict scan (opt-in) ----
    #
    # Unlike the neverallow scan above, this is OFF by default and only runs
    # under --check-mlsconstrains.  Rationale: an mlsconstrain is a RUNTIME
    # constraint, so a conflict here does NOT break a CIL recompile the way a
    # neverallow conflict does — it just means the injected allow may be
    # denied at runtime by the MLS layer.  Auto-relaxing MLS on every patch
    # run would silently loosen policy, so we require the user to ask for it.
    # When enabled, it mirrors the neverallow flow: scan, prompt, widen the
    # offending constraints with an (eq t1 sepinject_mlsaux_*) exemption, and
    # let the end-of-run SHA-256 recompute pick up the CIL change.
    if rules and args.check_mlsconstrains:
        print("\n[*] Pre-flight mlsconstrain conflict scan (--check-mlsconstrains)")

        mls_cil_paths: list = []
        if sys_selinux:
            mls_cil_paths.append(('plat', sys_selinux / 'plat_sepolicy.cil'))
        if not args.plat_cil_only:
            if vendor_selinux:
                mls_cil_paths.append(('vendor', vendor_selinux / 'vendor_sepolicy.cil'))
                ppv_path = vendor_selinux / 'plat_pub_versioned.cil'
                if ppv_path.exists():
                    mls_cil_paths.append(('plat_pub_versioned', ppv_path))
            if system_ext_selinux:
                mls_cil_paths.append(('system_ext',
                                      system_ext_selinux / 'system_ext_sepolicy.cil'))

        mls_conflicts: list = []
        mc_attr_map: dict = {}
        mc_all_types: set = set()
        if mls_cil_paths:
            mls_conflicts, mc_attr_map, mc_all_types = \
                find_mlsconstrain_conflicts(rules, mls_cil_paths)

        if mls_conflicts:
            if args.assume_yes:
                print("\n[*] --yes/--assume-yes — skipping mlsconstrain prompt.")
                mls_proceed = True
            else:
                mls_proceed = prompt_mlsconstrain_conflicts(mls_conflicts)
            if not mls_proceed:
                print("\n[!] User declined mlsconstrain rewrites.")
                if rollback is None:
                    # Nothing has been modified yet — exit cleanly.
                    print("[!] No files have been modified yet; exiting cleanly.")
                    sys.exit(2)
                else:
                    # Neverallow rewrites were already applied this run; keep
                    # them and simply skip the MLS widening.
                    print("[!] Keeping neverallow rewrites already applied; "
                          "skipping MLS widening.")
                    mlsconstrain_rewrites_ok = None
            else:
                # Create the rollback session now if the neverallow pass didn't.
                if rollback is None:
                    rollback = RollbackSession()
                    print(f"\n[*] Rollback snapshot dir: {rollback.session_dir}")
                for _, cil_p in mls_cil_paths:
                    if cil_p and cil_p.exists():
                        rollback.snapshot(cil_p)
                # Snapshot SHA-256 sidecars (they'll be recomputed at end of run).
                if sys_selinux:
                    rollback.snapshot(sys_selinux / 'plat_sepolicy_and_mapping.sha256')
                if vendor_selinux:
                    rollback.snapshot(vendor_selinux /
                                      'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256')
                if system_ext_selinux:
                    rollback.snapshot(system_ext_selinux /
                                      'system_ext_sepolicy_and_mapping.sha256')
                    if vendor_selinux:
                        rollback.snapshot(vendor_selinux /
                                          'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256')
                try:
                    mls_results = apply_mlsconstrain_rewrites(
                        mls_conflicts, rollback,
                        all_cil_paths=mls_cil_paths,
                        attr_map=mc_attr_map,
                        all_types=mc_all_types,
                    )
                    mlsconstrain_rewrites_ok = (all(mls_results.values())
                                                if mls_results else True)
                except Exception as e:
                    print(f"\n[!] mlsconstrain rewrite failed: {e}")
                    rollback.revert()
                    sys.exit(1)
        else:
            print("  [OK] No mlsconstrain conflicts detected")
            mlsconstrain_rewrites_ok = None  # no work needed

    # ---- Task 1: Patch binary sepolicy files (add rules) ----
    binary_results: dict[str, bool] = {}
    if policies and rules:
        helper = get_or_compile_helper()
        for pol in policies:
            ok = patch_policy(helper, rules_json, pol)
            binary_results[str(pol)] = ok
    elif policies and not rules:
        print("[~] No add rules — skipping binary add pass")
    elif not args.skip_binary:
        print("[~] No binary policy files to patch")


    # ---- Task 1b: Remove rules from binary sepolicy files ----
    binary_remove_results: dict[str, bool] = {}
    if policies and remove_rules:
        binary_remove_rules = [r for r in remove_rules
                               if r.op in ('remove_allow', 'remove_genfscon', 'remove_permissive')]
        if binary_remove_rules:
            helper = get_or_compile_helper()
            for pol in policies:
                ok = patch_policy(helper, remove_json, pol)
                binary_remove_results[str(pol)] = ok
    elif remove_rules and not policies:
        print("[~] No binary policy files — skipping binary remove pass")

    # ---- Task 2: Remove CIL entries (before adding new ones) ----
    cil_remove_ok: Optional[bool] = None
    if remove_rules and not args.skip_cil:
        if sys_selinux:
            cil_path = sys_selinux / 'plat_sepolicy.cil'
            cil_remove_ok = remove_from_cil(cil_path, remove_rules)
        else:
            print("[~] No system selinux dir — skipping CIL removal")

    # ---- Task 3: Add CIL entries ----
    #
    # This task does three things in order:
    #
    #   1. Detect any new domain types being declared in `rules`, and (unless
    #      --no-auto-coredomain is set) synthesize typeattribute rules placing
    #      them into coredomain. This is critical: Treble policy splits enforce
    #      neverallow rules like "no non-coredomain domain may do X" and a new
    #      plat-side domain that isn't in coredomain trips dozens of these,
    #      causing the CIL recompile to fail. We add the attribution rules to
    #      the user-supplied rule list before CIL emission so they all land in
    #      plat_sepolicy.cil in one append pass.
    #
    #   2. Apply vendor-side typeattributeset augmentations from
    #      --vendor-attr-add. These extend existing attribute sets in
    #      vendor_sepolicy.cil without re-declaring any types (which would
    #      cause a duplicate-declaration compile error). Used when a new
    #      plat-side type needs to be visible to vendor rules through a
    #      vendor-defined attribute set.
    #
    #   3. Patch plat_sepolicy.cil with the (now-augmented) rule list.
    #
    cil_ok: Optional[bool] = None
    vendor_aug_ok: Optional[bool] = None
    if not args.skip_cil:
        if sys_selinux:
            cil_path = sys_selinux / 'plat_sepolicy.cil'

            # Step 1: Auto-coredomain attribution
            auto_coredomain_rules: list = []
            if rules and not args.no_auto_coredomain:
                detected = detect_new_domains(rules)
                if detected:
                    print(f"\n[*] Detected new domain(s): {', '.join(sorted(detected))}")
                    # Collect every CIL we might find existing coredomain
                    # membership in.  Without this, every process-class
                    # type_transition default (e.g. `... :process shell`)
                    # gets re-added to coredomain even though it's
                    # already a coredomain in the live policy.
                    coredomain_scan_paths: list = [cil_path]
                    ppv_path = sys_selinux / 'plat_pub_versioned.cil'
                    if ppv_path.exists():
                        coredomain_scan_paths.append(ppv_path)
                    if system_ext_selinux:
                        sx = system_ext_selinux / 'system_ext_sepolicy.cil'
                        if sx.exists():
                            coredomain_scan_paths.append(sx)
                    auto_coredomain_rules = synthesize_coredomain_rules(
                        detected, rules, cil_paths=coredomain_scan_paths)
                    if auto_coredomain_rules:
                        names = ', '.join(sorted(r.type_name for r in auto_coredomain_rules))
                        print(f"  [+] Auto-attributing to coredomain: {names}")
                    else:
                        print(f"  [~] All detected domains already have explicit "
                              f"coredomain attribution")

            # Explicit --coredomain entries (additive, idempotent)
            explicit_coredomain_rules: list = []
            if args.coredomain:
                for t in args.coredomain:
                    # Skip ones already covered by auto-attribution
                    already = any(r.type_name == t and r.attr == _CORE_ATTRIBUTE
                                  for r in (rules + auto_coredomain_rules))
                    if already:
                        continue
                    explicit_coredomain_rules.append(TeRule(
                        op='typeattribute',
                        type_name=t,
                        attr=_CORE_ATTRIBUTE,
                    ))
                if explicit_coredomain_rules:
                    names = ', '.join(r.type_name for r in explicit_coredomain_rules)
                    print(f"  [+] Explicit --coredomain attribution: {names}")

            # Combined rule list for CIL emission
            all_cil_rules = rules + auto_coredomain_rules + explicit_coredomain_rules

            # Step 2: Vendor-side typeattributeset augmentations
            if args.vendor_attr_add and vendor_selinux:
                # Parse ATTR=TYPE1,TYPE2 entries
                vendor_augmentations: dict[str, list[str]] = {}
                for entry in args.vendor_attr_add:
                    if '=' not in entry:
                        print(f"  [!] Invalid --vendor-attr-add entry "
                              f"(expected ATTR=TYPE1,TYPE2): {entry}")
                        continue
                    attr, types_csv = entry.split('=', 1)
                    types_list = [t.strip() for t in types_csv.split(',') if t.strip()]
                    if not types_list:
                        continue
                    vendor_augmentations.setdefault(attr.strip(), []).extend(types_list)

                if vendor_augmentations:
                    vendor_cil = vendor_selinux / 'vendor_sepolicy.cil'
                    vendor_aug_ok = patch_vendor_cil_augmentations(
                        vendor_cil, vendor_augmentations)
            elif args.vendor_attr_add and not vendor_selinux:
                print("[~] --vendor-attr-add provided but no vendor selinux dir resolved")

            # Step 3: Apply all CIL additions to plat_sepolicy.cil
            if all_cil_rules:
                cil_ok = patch_cil(cil_path, all_cil_rules)
            else:
                print("[~] No add rules — skipping CIL add pass")
        else:
            print("[~] No system selinux dir — skipping CIL patch (use --system-selinux)")

    # ---- Task 4: plat_seapp_contexts (remove first, then add) ----
    seapp_remove_ok: Optional[bool] = None
    if not args.skip_seapp and seapp_remove_entries:
        if sys_selinux:
            seapp_remove_ok = remove_seapp_contexts(
                sys_selinux / 'plat_seapp_contexts', seapp_remove_entries)
        else:
            print("[~] No system selinux dir — skipping seapp_contexts removal")

    seapp_ok: Optional[bool] = None
    if not args.skip_seapp and seapp_entries:
        if sys_selinux:
            seapp_ok = patch_seapp_contexts(sys_selinux / 'plat_seapp_contexts', seapp_entries)
        else:
            print("[~] No system selinux dir — skipping seapp_contexts patch")
    elif not seapp_entries and not args.skip_seapp and not seapp_remove_entries:
        print("[~] No --seapp file provided — skipping seapp_contexts patch")

    # ---- Task 5: plat_file_contexts ----
    # Always ensure /system/etc/init and its RC files have a valid label.
    # Without this, any .rc file placed in /system/etc/init (including ksu.rc)
    # gets the 'unlabeled' context, which SELinux denies in enforcing mode —
    # causing init to silently skip the file and the trigger never fires.
    # We also label the vendor_boot/cpio_tree equivalents for completeness.
    INIT_DIR_FILE_CONTEXTS = [
        # system partition init RC directory
        r'/system/etc/init(/.*)?	u:object_r:system_file:s0',
        # vendor_boot ramdisk init RC directory (covers recovery and first-stage)
        r'/vendor/etc/init(/.*)?	u:object_r:vendor_file:s0',
    ]
    auto_file_ctx: list[str] = []
    if sys_selinux and not args.skip_file_contexts:
        existing_fc = (sys_selinux / 'plat_file_contexts').read_text(errors='replace')
        for entry in INIT_DIR_FILE_CONTEXTS:
            # Check whether /system/etc/init is already covered by any existing rule
            path_part = entry.split()[0]
            # Strip regex suffixes to get the bare path for a coverage check
            bare = path_part.rstrip('(/.*)?').rstrip('(')
            if bare not in existing_fc:
                auto_file_ctx.append(entry)
        if auto_file_ctx:
            print(f"\n[*] Auto-injecting {len(auto_file_ctx)} missing init-dir file_contexts entry/entries")

    combined_file_ctx = auto_file_ctx + file_ctx_entries

    file_ctx_ok: Optional[bool] = None
    if not args.skip_file_contexts and combined_file_ctx:
        if sys_selinux:
            file_ctx_ok = patch_file_contexts(sys_selinux / 'plat_file_contexts', combined_file_ctx)
        else:
            print("[~] No system selinux dir — skipping file_contexts patch")
    elif not combined_file_ctx and not args.skip_file_contexts:
        print("[~] No --file-contexts file provided — skipping file_contexts patch")

    # ---- Task 6: property_contexts ----
    # Written to both system plat_property_contexts AND vendor_property_contexts
    # (same entries are needed in both for properties crossing the partition boundary)
    prop_ctx_plat_ok: Optional[bool] = None
    prop_ctx_vendor_ok: Optional[bool] = None
    if not args.skip_property_contexts and prop_ctx_entries:
        if sys_selinux:
            plat_prop = sys_selinux / PLAT_PROPERTY_CONTEXTS
            prop_ctx_plat_ok = patch_property_contexts(plat_prop, prop_ctx_entries)
        else:
            print("[~] No system selinux dir — skipping plat_property_contexts patch")
        if vendor_selinux:
            vendor_prop = vendor_selinux / VENDOR_PROPERTY_CONTEXTS
            if vendor_prop.exists():
                prop_ctx_vendor_ok = patch_property_contexts(vendor_prop, prop_ctx_entries)
            else:
                print(f"  [~] vendor_property_contexts not found, skipping: {vendor_prop}")
    elif not prop_ctx_entries and not args.skip_property_contexts:
        print("[~] No --property-contexts file provided — skipping property_contexts patch")

    # ---- Task 7: service_contexts ----
    svc_ctx_ok: Optional[bool] = None
    if not args.skip_service_contexts and svc_ctx_entries:
        if sys_selinux:
            svc_ctx_ok = patch_service_contexts(
                sys_selinux / PLAT_SERVICE_CONTEXTS, svc_ctx_entries)
        else:
            print("[~] No system selinux dir — skipping service_contexts patch")
    elif not svc_ctx_entries and not args.skip_service_contexts:
        print("[~] No --service-contexts file provided — skipping service_contexts patch")

    # ---- Task 8: hwservice_contexts ----
    # Written to system plat_hwservice_contexts if present, else vendor_hwservice_contexts
    hwsvc_ctx_plat_ok: Optional[bool] = None
    hwsvc_ctx_vendor_ok: Optional[bool] = None
    if not args.skip_hwservice_contexts and hwsvc_ctx_entries:
        if sys_selinux:
            plat_hw = sys_selinux / PLAT_HWSERVICE_CONTEXTS
            if plat_hw.exists():
                hwsvc_ctx_plat_ok = patch_hwservice_contexts(plat_hw, hwsvc_ctx_entries)
            else:
                print(f"  [~] plat_hwservice_contexts not found: {plat_hw}")
        if vendor_selinux:
            vendor_hw = vendor_selinux / VENDOR_HWSERVICE_CONTEXTS
            if vendor_hw.exists():
                hwsvc_ctx_vendor_ok = patch_hwservice_contexts(vendor_hw, hwsvc_ctx_entries)
            else:
                print(f"  [~] vendor_hwservice_contexts not found: {vendor_hw}")
        if not hwsvc_ctx_plat_ok and not hwsvc_ctx_vendor_ok:
            print("[~] No hwservice_contexts files found — skipping hwservice_contexts patch")
    elif not hwsvc_ctx_entries and not args.skip_hwservice_contexts:
        print("[~] No --hwservice-contexts file provided — skipping hwservice_contexts patch")

    # ---- Task 9: Recompute SHA-256 ----
    sha_ok: Optional[bool] = None
    # Recompute the hash whenever CIL changed OR when the binary sync ran
    # (because the sync writes a new precompiled_sepolicy which may differ from
    # what the existing sidecar .sha256 was computed against).
    # Note: cil_changed now also accounts for neverallow rewrites, which may
    # have modified plat / vendor / system_ext CILs.  vendor_aug_ok is also
    # included since augmenting vendor CIL changes its hash too.
    cil_changed = (bool(cil_ok) or bool(cil_remove_ok)
                   or bool(neverallow_rewrites_ok) or bool(vendor_aug_ok)
                   or bool(mlsconstrain_rewrites_ok))
    if not args.skip_sha256 and cil_changed:
        if sys_selinux:
            sha_ok = update_sha256(sys_selinux, vendor_selinux, system_ext_selinux)
        else:
            print("[~] No system selinux dir — skipping SHA-256 update")

    # ---- Summary ----
    print("\n" + "=" * 60)
    print("[*] Summary")
    print("=" * 60)

    all_ok = True

    def _status(result: Optional[bool], label: str):
        nonlocal all_ok
        if result is None:
            print(f"    [--] {label} (skipped)")
        elif result:
            print(f"    [OK] {label}")
        else:
            print(f"    [FAILED] {label}")
            all_ok = False

    if binary_results:
        print("\n  Binary policy (add rules):")
        for path, ok in binary_results.items():
            status = "OK" if ok else "FAILED"
            print(f"    [{status}] {path}")
            if not ok:
                all_ok = False

    if binary_remove_results:
        print("\n  Binary policy (remove rules):")
        for path, ok in binary_remove_results.items():
            status = "OK" if ok else "FAILED"
            print(f"    [{status}] {path}")
            if not ok:
                all_ok = False

    print("\n  CIL / policy patches:")
    _status(cil_remove_ok,      "plat_sepolicy.cil (removals)")
    _status(cil_ok,             "plat_sepolicy.cil (additions)")
    _status(vendor_aug_ok,      "vendor_sepolicy.cil (attribute augmentations)")
    _status(neverallow_rewrites_ok, "neverallow rewrites (CIL)")
    _status(mlsconstrain_rewrites_ok, "mlsconstrain rewrites (CIL)")

    print("\n  Context file patches:")
    _status(seapp_remove_ok,    "plat_seapp_contexts (removals)")
    _status(seapp_ok,           "plat_seapp_contexts (additions)")
    _status(file_ctx_ok,        "plat_file_contexts")
    _status(prop_ctx_plat_ok,   "plat_property_contexts")
    _status(prop_ctx_vendor_ok, "vendor_property_contexts")
    _status(svc_ctx_ok,         "plat_service_contexts")
    _status(hwsvc_ctx_plat_ok,  "plat_hwservice_contexts")
    _status(hwsvc_ctx_vendor_ok,"vendor_hwservice_contexts")

    print("\n  Integrity:")
    _status(sha_ok,             "plat_sepolicy_and_mapping.sha256")

    # Finalize the rollback session.  On success, commits the snapshot dir
    # (keeps the pre-run state captured at /tmp/sepinject-rollback-... for
    # manual recovery).  On failure, attempt to revert.
    # The rollback session is only created if neverallow rewrites were applied,
    # so we guard the access here.
    if rollback is not None:
        if all_ok:
            rollback.commit()
        else:
            # Partial failure — leave snapshot in place but mention it so the
            # user can manually revert if they want.
            if rollback.snapshots:
                print(f"\n[!] One or more steps failed; pre-run snapshot is available at:")
                print(f"    {rollback.session_dir}")
                print(f"    ({len(rollback.snapshots)} file(s)). "
                      f"You can manually restore them if needed.")

    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
