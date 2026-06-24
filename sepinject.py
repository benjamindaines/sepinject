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
                    return [x.strip() for x in s.strip('{}').split() if x.strip()]
                return [s] if s != '~all' else []  # skip complement for now

            srcs = extract_set(raw_src)
            tgts = extract_set(raw_tgt)
            clss = extract_set(raw_cls)
            perms = extract_set(raw_perms)

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
                    for c in extract_set(raw_cls):
                        rules.append(RemoveRule(
                            op='remove_allow', src=s, tgt=t, cls=c,
                            perms=extract_set(raw_perms)
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

import time



@dataclass
class CilNeverallow:
    """A single (neverallow ...) statement parsed from a CIL file."""
    cil_path: Path
    line_no: int            # 1-based line in the source file
    raw_line: str           # exact text of the line, including trailing \n if present
    src_expr: str           # raw S-expression for the source (e.g. "appdomain" or "(and (a) (not (b)))")
    tgt_expr: str           # raw S-expression for the target
    cls: str                # class name (e.g. "file")
    perms: list             # list of permission names (e.g. ["read","write"])


@dataclass
class NeverallowConflict:
    """A detected conflict between a proposed allow rule and an existing neverallow."""
    rule: 'TeRule'                  # the proposed allow rule
    neverallow: CilNeverallow       # the matching neverallow
    matched_perms: list             # list of perm names from rule.perms that the neverallow covers
    structural: bool                # True if the rule's class fully matches but with all perms; False if specific perms
    # If structural: rewrite by subtracting src from neverallow's src expression
    # If not structural: rewrite by dropping matched_perms from neverallow's perm list


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

       Returns a list of CilNeverallow objects.
    """
    if not cil_path.exists():
        return []

    results = []
    skipped = 0
    text = cil_path.read_text(errors='replace')
    for idx, raw_line in enumerate(text.splitlines(keepends=True), start=1):
        stripped = raw_line.lstrip()
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
    return results


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
        return {expr}

    if not isinstance(expr, list) or not expr:
        return None

    op = expr[0]
    args = expr[1:]

    if op not in ('and', 'or', 'not', 'xor', 'all'):
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
        if not args:
            return set()
        inner = _na_resolve_set(args[0], attr_map, all_types, visiting)
        if inner is None:
            return None
        return set(all_types) - inner

    if op == 'xor':
        if len(args) < 2:
            return None
        a = _na_resolve_set(args[0], attr_map, all_types, visiting)
        b = _na_resolve_set(args[1], attr_map, all_types, visiting)
        if a is None or b is None:
            return None
        return a ^ b

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

def find_neverallow_conflicts(rules: list, cil_paths: list) -> list:
    """For each `allow` rule in `rules`, scan all neverallows across the given
       CIL files and return a list of NeverallowConflict objects describing
       any conflicts.

       cil_paths is a list of (label, Path) tuples; only Paths that exist are
       processed.

       A conflict exists when ALL of:
         - rule.src ∈ resolve(neverallow.src_expr)
         - rule.tgt ∈ resolve(neverallow.tgt_expr)  (or 'self' handling)
         - rule.cls == neverallow.cls
         - any p ∈ rule.perms that is also in neverallow.perms
    """
    conflicts = []

    for label, cil_path in cil_paths:
        if not cil_path or not cil_path.exists():
            continue
        print(f"  [*] Scanning {label}: {cil_path.name}")
        neverallows = parse_cil_neverallows(cil_path)
        if not neverallows:
            print(f"      no neverallows parsed")
            continue
        print(f"      {len(neverallows)} neverallow(s) found")
        attr_map = parse_cil_typeattributesets(cil_path)
        all_types = collect_all_type_names(cil_path)

        resolved_cache: dict = {}

        for rule in rules:
            if rule.op != 'allow':
                continue
            if not rule.cls or not rule.perms:
                continue
            for na in neverallows:
                if na.cls != rule.cls:
                    continue
                matched = [p for p in rule.perms if p in na.perms]
                if not matched:
                    continue
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

                src_match = (src_set is None) or (rule.src in src_set)
                if rule.tgt == 'self':
                    tgt_match = True
                else:
                    tgt_match = (tgt_set is None) or (rule.tgt in tgt_set)

                if src_match and tgt_match:
                    structural = all(p in na.perms for p in rule.perms) and \
                                 len(matched) == len(rule.perms)
                    conflicts.append(NeverallowConflict(
                        rule=rule,
                        neverallow=na,
                        matched_perms=matched,
                        structural=structural,
                    ))

    return conflicts


# ----- Rewrite generation -----

def build_rewrite(conflict: NeverallowConflict) -> str:
    """Construct the rewritten neverallow line.

       Strategy: drop the offending perm(s) from the perm list.
       If that leaves the perm list empty, the neverallow becomes vacuous
       and we instead subtract the offending src from the source expression.
    """
    na = conflict.neverallow
    remaining_perms = [p for p in na.perms if p not in conflict.matched_perms]

    if remaining_perms:
        if len(remaining_perms) == 1:
            perms_str = remaining_perms[0]
        else:
            perms_str = '(' + ' '.join(remaining_perms) + ')'
        return f"(neverallow {na.src_expr} {na.tgt_expr} ({na.cls} {perms_str}))"

    new_src = f"(and {na.src_expr} (not ({conflict.rule.src})))"
    if len(na.perms) == 1:
        perms_str = na.perms[0]
    else:
        perms_str = '(' + ' '.join(na.perms) + ')'
    return f"(neverallow {new_src} {na.tgt_expr} ({na.cls} {perms_str}))"


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
        path = Path(path)
        if not path.exists():
            return
        if any(orig == path for orig, _ in self.snapshots):
            return  
        rel = str(path).lstrip('/').replace(':', '_')
        snap = self.session_dir / rel
        snap.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, snap)
        self.snapshots.append((path, snap))

    def revert(self) -> None:
        print(f"\n[!] Reverting {len(self.snapshots)} file(s) from rollback session...")
        for orig, snap in self.snapshots:
            try:
                shutil.copy2(snap, orig)
                print(f"  [-] Restored: {orig}")
            except Exception as e:
                print(f"  [!] Failed to restore {orig}: {e}")
        print(f"[!] Rollback complete. Snapshot dir retained: {self.session_dir}")

    def commit(self) -> None:
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
        if c.structural:
            print(f"    Rewrite:   (will subtract '{rule.src}' from source set)")
        else:
            print(f"    Rewrite:   (will drop matched perm(s) from neverallow's perm list)")
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

def apply_neverallow_rewrites(conflicts: list, rollback: RollbackSession) -> dict:
    """Group conflicts by CIL file and apply the rewrites.  Each conflicting
       neverallow line is commented out (prefixed with ';; sepinject: ') and a
       rewritten version is inserted on the next line, prefixed with a marker
       comment for traceability.

       Returns a dict mapping cil_path -> True/False (whether changes were made).
       The rollback session is updated to snapshot each CIL before mutation.
    """
    # Group by file
    by_file: dict = {}
    for c in conflicts:
        by_file.setdefault(c.neverallow.cil_path, []).append(c)

    results = {}
    for cil_path, file_conflicts in by_file.items():
        print(f"\n[*] Rewriting neverallows in: {cil_path}")
        rollback.snapshot(cil_path)

        text = cil_path.read_text(errors='replace')
        lines = text.splitlines(keepends=True)

        line_conflicts: dict = {}
        for c in file_conflicts:
            line_conflicts.setdefault(c.neverallow.line_no, []).append(c)

        new_lines = []
        modified = 0
        for idx, raw_line in enumerate(lines, start=1):
            if idx not in line_conflicts:
                new_lines.append(raw_line)
                continue

            cs = line_conflicts[idx]

            stripped_nl = raw_line.rstrip('\r\n')
            line_ending = raw_line[len(stripped_nl):]
            new_lines.append(f";; sepinject: commented (neverallow rewritten below)\n")
            new_lines.append(f";; {stripped_nl}{line_ending}")

            merged_matched = set()
            structural_any = False
            triggering_rules = []
            for c in cs:
                merged_matched.update(c.matched_perms)
                structural_any = structural_any or c.structural
                triggering_rules.append(c.rule)

            base_na = cs[0].neverallow
            merged_conflict = NeverallowConflict(
                rule=cs[0].rule,           # used only if structural fallback fires
                neverallow=base_na,
                matched_perms=sorted(merged_matched),
                structural=structural_any,
            )
            rewrite = build_rewrite(merged_conflict)

            trigger_summary = ', '.join(
                f"allow {r.src} {r.tgt}:{r.cls} {{{' '.join(r.perms)}}}"
                for r in triggering_rules
            )
            new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
            new_lines.append(rewrite + line_ending)
            modified += 1

        if modified:
            cil_path.write_text(''.join(new_lines))
            print(f"  [+] Rewrote {modified} neverallow line(s) in {cil_path.name}")
            results[cil_path] = True
        else:
            results[cil_path] = False

    return results


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
    if not policy_path.exists():
        print(f"  [!] Policy not found, skipping: {policy_path}")
        return False

    print(f"\n[*] Patching: {policy_path}")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
        tf.write(rules_json)
        tf_path = tf.name

    backup = policy_path.with_suffix(policy_path.suffix + '.bak')
    if not backup.exists():
        shutil.copy2(policy_path, backup)
        print(f"  [+] Backup: {backup}")

    try:
        result = subprocess.run(
            [str(helper), tf_path, str(policy_path)],
            capture_output=True, text=True
        )
        for line in result.stderr.splitlines():
            print(f"  {line}")
        if result.returncode != 0:
            print(f"  [!] Helper exited with code {result.returncode}")
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
            for tname in type_names_to_remove:
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

    with open(cil_path, 'a') as f:
        f.write('\n'.join(new_lines))

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
ROM_SYSTEM_EXT_SELINUX = 'system_ext/fs_tree/system_ext/etc/selinux'

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

    args = parser.parse_args()

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
                dr_conflicts = find_neverallow_conflicts(rules, dr_cils)
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

    if rules and not args.skip_neverallow_check:
        print("\n[*] Pre-flight neverallow conflict scan")

        # Build the list of CIL files to scan.  Plat is always included if
        # available; vendor and system_ext are included unless --plat-cil-only.
        cil_paths_to_scan: list = []
        if sys_selinux:
            cil_paths_to_scan.append(('plat', sys_selinux / 'plat_sepolicy.cil'))
        if not args.plat_cil_only:
            if vendor_selinux:
                cil_paths_to_scan.append(('vendor', vendor_selinux / 'vendor_sepolicy.cil'))
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

        conflicts: list = []
        if cil_paths_to_scan:
            conflicts = find_neverallow_conflicts(rules, cil_paths_to_scan)

        if conflicts or binary_findings:
            proceed = prompt_neverallow_conflicts(conflicts, binary_findings)
            if not proceed:
                print("\n[!] User declined neverallow rewrites.")
                print("[!] No files have been modified yet; exiting cleanly.")
                # No rollback was created; we haven't touched anything.
                sys.exit(2)

            # Create the rollback session — this is the
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
                rewrite_results = apply_neverallow_rewrites(conflicts, rollback)
                neverallow_rewrites_ok = all(rewrite_results.values()) if rewrite_results else True
            except Exception as e:
                print(f"\n[!] Neverallow rewrite failed: {e}")
                rollback.revert()
                sys.exit(1)
        else:
            print("  [OK] No neverallow conflicts detected")
            neverallow_rewrites_ok = None  # no work needed

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

    cil_remove_ok: Optional[bool] = None
    if remove_rules and not args.skip_cil:
        if sys_selinux:
            cil_path = sys_selinux / 'plat_sepolicy.cil'
            cil_remove_ok = remove_from_cil(cil_path, remove_rules)
        else:
            print("[~] No system selinux dir — skipping CIL removal")

    cil_ok: Optional[bool] = None
    if not args.skip_cil:
        if sys_selinux:
            cil_path = sys_selinux / 'plat_sepolicy.cil'
            if rules:
                cil_ok = patch_cil(cil_path, rules)
            else:
                print("[~] No add rules — skipping CIL add pass")
        else:
            print("[~] No system selinux dir — skipping CIL patch (use --system-selinux)")

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

    INIT_DIR_FILE_CONTEXTS = [
        r'/system/etc/init(/.*)?	u:object_r:system_file:s0',
        r'/vendor/etc/init(/.*)?	u:object_r:vendor_file:s0',
    ]
    auto_file_ctx: list[str] = []
    if sys_selinux and not args.skip_file_contexts:
        existing_fc = (sys_selinux / 'plat_file_contexts').read_text(errors='replace')
        for entry in INIT_DIR_FILE_CONTEXTS:
            path_part = entry.split()[0]
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

    svc_ctx_ok: Optional[bool] = None
    if not args.skip_service_contexts and svc_ctx_entries:
        if sys_selinux:
            svc_ctx_ok = patch_service_contexts(
                sys_selinux / PLAT_SERVICE_CONTEXTS, svc_ctx_entries)
        else:
            print("[~] No system selinux dir — skipping service_contexts patch")
    elif not svc_ctx_entries and not args.skip_service_contexts:
        print("[~] No --service-contexts file provided — skipping service_contexts patch")

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

    sha_ok: Optional[bool] = None
    cil_changed = bool(cil_ok) or bool(cil_remove_ok) or bool(neverallow_rewrites_ok)
    if not args.skip_sha256 and cil_changed:
        if sys_selinux:
            sha_ok = update_sha256(sys_selinux, vendor_selinux, system_ext_selinux)
        else:
            print("[~] No system selinux dir — skipping SHA-256 update")

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
    _status(neverallow_rewrites_ok, "neverallow rewrites (CIL)")

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

    if rollback is not None:
        if all_ok:
            rollback.commit()
        else:
            if rollback.snapshots:
                print(f"\n[!] One or more steps failed; pre-run snapshot is available at:")
                print(f"    {rollback.session_dir}")
                print(f"    ({len(rollback.snapshots)} file(s)). "
                      f"You can manually restore them if needed.")

    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
