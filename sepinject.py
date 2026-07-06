
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
@dataclass


class  TeRule:
    op: str
    src: str = ""
    tgt: str = ""
    cls: str = ""
    perms: list = field(default_factory=list)
    type_name: str = ""
    attr: str = ""
    default: str = ""
    tr_name: str = ""
    fs_type: str = ""   
    path: str = ""      
    context: str = ""   
@dataclass


class  RemoveRule:
    op: str          
    src: str = ""    
    tgt: str = ""    
    cls: str = ""
    perms: list = field(default_factory=list)
    type_name: str = ""
    attr: str = ""


def  _strip_comments(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'#[^\n]*', '', text)
    return text


def  _expand_te_macros(text: str) -> str:
    macro_call_re = re.compile(
        r'\b(init_daemon_domain|domain_auto_trans|domain_trans|set_prop|get_prop|'
        r'binder_use|binder_call|binder_service|unix_socket_connect)\s*'
        r'\(([^)]*)\)\s*;?',
        re.MULTILINE,
    )


    def  expand_one(match: 're.Match') -> str:
        name = match.group(1)
        args = [a.strip() for a in match.group(2).split(',') if a.strip()]
        try:
            rules = _MACRO_DEFINITIONS[name](*args)
        except (TypeError, KeyError) as e:
            print(f"  [!] macro {name}({', '.join(args)}): {e}; left in place")
            return match.group(0)
        return '\n' + '\n'.join(rules) + '\n'
    return macro_call_re.sub(expand_one, text)


def  _macro_init_daemon_domain(d: str) -> list[str]:
    return [
        f"type {d}, domain, coredomain;",
        f"allow init {d}:process transition;",
        f"allow init {d}:process {  siginh rlimitinh noatsecure } ;",
        f"allow {d} {d}_exec:file {  entrypoint open read execute getattr map } ;",
        f"allow {d} init:fd use;",
        f"type_transition init {d}_exec:process {d};",
    ]


def  _macro_domain_auto_trans(src: str, exec_t: str, dst: str) -> list[str]:
    return [
        f"allow {src} {exec_t}:file {  getattr open read execute map } ;",
        f"allow {src} {dst}:process transition;",
        f"allow {dst} {exec_t}:file {  entrypoint open read execute getattr map } ;",
        f"allow {dst} {src}:fd use;",
        f"type_transition {src} {exec_t}:process {dst};",
        f"allow {src} {dst}:process {  siginh rlimitinh noatsecure } ;",
    ]


def  _macro_domain_trans(src: str, exec_t: str, dst: str) -> list[str]:
    return [
        f"allow {src} {exec_t}:file {  getattr open read execute map } ;",
        f"allow {src} {dst}:process transition;",
        f"allow {dst} {exec_t}:file {  entrypoint open read execute getattr map } ;",
        f"allow {dst} {src}:fd use;",
        f"allow {src} {dst}:process {  siginh rlimitinh noatsecure } ;",
    ]


def  _macro_set_prop(d: str, p: str) -> list[str]:
    return [
        f"allow {d} {p}:property_service set;",
        f"allow {d} property_socket:sock_file write;",
        f"allow {d} init:unix_stream_socket connectto;",
    ]


def  _macro_get_prop(d: str, p: str) -> list[str]:
    return [
        f"allow {d} {p}:file {  getattr open read map } ;",
    ]


def  _macro_binder_use(d: str) -> list[str]:
    return [
        f"allow {d} servicemanager:binder {  call transfer } ;",
        f"allow servicemanager {d}:binder transfer;",
        f"allow servicemanager {d}:dir search;",
        f"allow servicemanager {d}:file {  read open } ;",
        f"allow servicemanager {d}:process getattr;",
    ]


def  _macro_binder_call(src: str, dst: str) -> list[str]:
    return [
        f"allow {src} {dst}:binder {  call transfer } ;",
        f"allow {dst} {src}:binder transfer;",
        f"allow {src} {dst}:fd use;",
    ]


def  _macro_binder_service(d: str) -> list[str]:
    return [
        f"typeattribute {d} binderservicedomain;",
    ]


def  _macro_unix_socket_connect(d: str, sock: str, server: str) -> list[str]:
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
# https://android.googlesource.com/platform/system/sepolicy/+/main/public/global_macros 
_GLOBAL_PERM_MACROS: dict[str, str] = {
    'x_file_perms':         'getattr execute execute_no_trans map',
    'r_file_perms':         'getattr open read ioctl lock map watch watch_reads',
    'w_file_perms':         'open append write lock map',
    'rx_file_perms':        'r_file_perms x_file_perms',
    'ra_file_perms':        'r_file_perms append',
    'rw_file_perms':        'r_file_perms w_file_perms',
    'rwx_file_perms':       'rw_file_perms x_file_perms',
    'create_file_perms':    'create rename setattr unlink rw_file_perms',
    'r_dir_perms':          'open getattr read search ioctl lock watch watch_reads',
    'w_dir_perms':          'open search write add_name remove_name lock',
    'ra_dir_perms':         'r_dir_perms add_name write',
    'rw_dir_perms':         'r_dir_perms w_dir_perms',
    'create_dir_perms':     'create reparent rename rmdir setattr rw_dir_perms',
    'r_ipc_perms':          'getattr read associate unix_read',
    'w_ipc_perms':          'write unix_write',
    'rw_ipc_perms':         'r_ipc_perms w_ipc_perms',
    'create_ipc_perms':     'create setattr destroy rw_ipc_perms',
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
}


def  _resolve_macros(items: list[str], macros: dict[str, str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()


    def  walk(token: str, depth: int) -> None:
        if depth > 16:
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


def  _expand_braces(tokens: list[str]) -> list[list[str]]:


    def  expand_one(toks: list[str]) -> list[list[str]]:
        try:
            start = toks.index('{')
            end = toks.index('}', start)
        except ValueError:
            return [toks]  
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


def  parse_te_file(path: str) -> list[TeRule]:
    text = Path(path).read_text(errors='replace')
    text = _strip_comments(text)
    text = _expand_te_macros(text)
    rules = []
    statements = text.split(';')
    for stmt in statements:
        stmt = stmt.strip()
        if not stmt:
            continue
        tokens = stmt.split()
        if not tokens:
            continue
        op = tokens[0]
        if op in ('allow', 'auditallow', 'dontaudit', 'neverallow'):
            if op == 'neverallow':
                print(f"  [~] Skipping neverallow (not enforceable at binary patch time)")
                continue
            rest = ' '.join(tokens[1:])
            m = re.match(
                r'(\{[^}]*\}|\S+)\s+'             
                r'(\{[^}]*\}|\S+)\s*:\s*'         
                r'(\{[^}]*\}|\S+)\s*'             
                r'(\{[^}]*\}|\S+)',               
                rest
            )
            if not m:
                print(f"  [!] Cannot parse rule: {op} {rest!r}")
                continue
            raw_src, raw_tgt, raw_cls, raw_perms = m.group(1), m.group(2), m.group(3), m.group(4)


            def  extract_set(s: str) -> list[str]:
                s = s.strip()
                if s.startswith('{'):
                    return [x for x in re.split(r'[\s,]+', s.strip('{}')) if x]
                return [s] if s != '~all' else []  
            srcs = extract_set(raw_src)
            tgts = extract_set(raw_tgt)
            clss = extract_set(raw_cls)
            perms = extract_set(raw_perms)
            perms = _resolve_macros(perms, _GLOBAL_PERM_MACROS)
            clss  = _resolve_macros(clss,  _GLOBAL_CLASS_MACROS)
            for s in srcs:
                for t in tgts:
                    for c in clss:
                        rules.append(TeRule(
                            op=op, src=s, tgt=t, cls=c, perms=perms
                        ))
        elif op == 'permissive':
            if len(tokens) >= 2:
                rules.append(TeRule(op='permissive', type_name=tokens[1]))
        elif op == 'type':
            if len(tokens) >= 2:
                name = tokens[1].rstrip(',')
                attrs = [t.strip(', ') for t in tokens[2:] if t.strip(', ')]
                if not attrs:
                    rules.append(TeRule(op='type', type_name=name))
                else:
                    rules.append(TeRule(op='type', type_name=name, attr=attrs[0]))
                    for a in attrs[1:]:
                        rules.append(TeRule(op='typeattribute', type_name=name, attr=a))
        elif op == 'attribute':
            if len(tokens) >= 2:
                rules.append(TeRule(op='attribute', type_name=tokens[1]))
        elif op == 'typeattribute':
            if len(tokens) >= 3:
                name = tokens[1]
                for attr in tokens[2:]:
                    attr = attr.strip(', ')
                    if attr:
                        rules.append(TeRule(op='typeattribute', type_name=name, attr=attr))
        elif op in ('mlstrustedsubject', 'mlstrustedobject'):
            if len(tokens) >= 2:
                for name in tokens[1:]:
                    name = name.strip(', ')
                    if name:
                        rules.append(TeRule(op='typeattribute',
                                            type_name=name, attr=op))
            else:
                print(f"  [!] {op}: expected at least one type name")
        elif op == 'type_transition':
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
        elif op == 'genfscon':
            rest_tokens = tokens[1:]
            if len(rest_tokens) >= 3:
                fs = rest_tokens[0]
                path = rest_tokens[1].strip('"').strip("'")
                ctx_tok = rest_tokens[2]
                if ctx_tok == '-f' and len(rest_tokens) >= 5:
                    ctx_tok = rest_tokens[4]
                elif ctx_tok == '-f' and len(rest_tokens) >= 4:
                    ctx_tok = rest_tokens[3]
                rules.append(TeRule(op='genfscon', fs_type=fs, path=path, context=ctx_tok))
            else:
                print(f"  [!] Cannot parse genfscon: {' '.join(tokens)!r}")
        elif op in ('require', 'optional', 'ifdef', 'ifndef', 'endif',
                    'class', 'common', 'inherits', 'typealias', 'typebounds',
                    'role', 'user', 'sid', 'sensitivity', 'category',
                    'level', 'mlsconstrain', 'mlsvalidatetrans',
                    'constrain', 'validatetrans', 'define', 'gen_require',
                    'bool', 'if', 'else'):
            pass  
        else:
            if op and not op.startswith('#'):
                print(f"  [~] Unrecognized keyword, skipping: {op!r}")
    return rules


def  parse_remove_te_file(path: str) -> list[RemoveRule]:
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


            def  extract_set(s: str) -> list[str]:
                s = s.strip()
                if s.startswith('{'):
                    return [x.strip() for x in s.strip('{}').split() if x.strip()]
                return [s]
            for s in extract_set(m.group(1)):
                for t in extract_set(raw_tgt):
                    for c in _resolve_macros(extract_set(raw_cls),
                                             _GLOBAL_CLASS_MACROS):
                        rules.append(RemoveRule(
                            op='remove_allow', src=s, tgt=t, cls=c,
                            perms=_resolve_macros(extract_set(raw_perms),
                                                  _GLOBAL_PERM_MACROS)
                        ))
        elif op == 'remove_genfscon':
            if len(tokens) >= 3:
                fs = tokens[1]
                path_val = tokens[2].strip('"').strip("'")
                rules.append(RemoveRule(op='remove_genfscon', src=fs, tgt=path_val))
            else:
                print(f"  [!] Cannot parse: {op} {' '.join(tokens[1:])!r}")
        elif op == 'remove_permissive':
            if len(tokens) >= 2:
                rules.append(RemoveRule(op='remove_permissive', type_name=tokens[1]))
        elif op == 'remove_type':
            if len(tokens) >= 2:
                rules.append(RemoveRule(op='remove_type', type_name=tokens[1]))
                print(f"  [~] remove_type '{tokens[1]}': CIL only (binary type removal not supported)")
        elif op == 'remove_typeattribute':
            if len(tokens) >= 3:
                rules.append(RemoveRule(op='remove_typeattribute',
                                        type_name=tokens[1], attr=tokens[2].strip(',')))
        elif op in ('remove_mlstrustedsubject', 'remove_mlstrustedobject'):
            attr = op[len('remove_'):]  
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


def  rules_to_json(rules: list[TeRule]) -> str:
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
            continue  
        out.append(obj)
    return json.dumps(out, indent=2)


def  remove_rules_to_json(rules: list[RemoveRule]) -> str:
    out = []
    for r in rules:
        if r.op == 'remove_allow':
            out.append({"op": "remove_allow",
                        "src": r.src, "tgt": r.tgt, "cls": r.cls, "perms": r.perms})
        elif r.op == 'remove_genfscon':
            out.append({"op": "remove_genfscon", "src": r.src, "tgt": r.tgt})
        elif r.op == 'remove_permissive':
            out.append({"op": "remove_permissive", "type": r.type_name})
    return json.dumps(out, indent=2)
import time
@dataclass


class  CilNeverallow:
    cil_path: Path
    line_no: int            
    raw_line: str           
    src_expr: str           
    tgt_expr: str           
    cls: str                
    perms: list             
    previously_rewritten: bool = False
    aux_name: Optional[str] = None        
    original_line_no: Optional[int] = None  
    live_raw_line: Optional[str] = None     
    prior_excluded_srcs: list = field(default_factory=list)  
    triggers_text: Optional[str] = None     
    rewrite_block_line_nos: set = field(default_factory=set)  
@dataclass


class  NeverallowConflict:
    rule: 'TeRule'                  
    neverallow: CilNeverallow       
    matched_perms: list             
    structural: bool                
    src_resolved: Optional[set] = None


def  _na_tokenize_sexpr(s: str) -> list:
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
        j = i
        while j < n and not s[j].isspace() and s[j] not in '()':
            j += 1
        tokens.append(s[i:j])
        i = j
    return tokens


def  _na_parse_sexpr(tokens: list, pos: int = 0):
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
            pos += 1  
        return children, pos
    elif tok == ')':
        return None, pos + 1
    else:
        return tok, pos + 1


def  _na_parse_sexpr_one(s: str):
    tokens = _na_tokenize_sexpr(s)
    if not tokens:
        return None
    val, _ = _na_parse_sexpr(tokens, 0)
    return val


def  parse_cil_neverallows(cil_path: Path) -> list:
    if not cil_path.exists():
        return []
    results = []
    skipped = 0
    text = cil_path.read_text(errors='replace')
    lines = text.splitlines(keepends=True)
    sepinject_blocks = _find_sepinject_blocks(lines)
    sepinject_block_lines: set = set()
    for b in sepinject_blocks.values():
        sepinject_block_lines.update(b['block_line_nos'])
    for idx, raw_line in enumerate(lines, start=1):
        if idx in sepinject_blocks:
            block = sepinject_blocks[idx]
            sexpr = _na_parse_sexpr_one(block['original_text'])
            if not (isinstance(sexpr, list) and len(sexpr) >= 4
                    and sexpr[0] == 'neverallow'):
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
                            line_no=idx,                
                            raw_line=block['original_text'],  
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
        if idx in sepinject_block_lines:
            continue
        stripped = raw_line.lstrip()
        if not stripped or stripped.startswith(';'):
            continue
        if not (stripped.startswith('(neverallow ') or stripped.startswith('(neverallow\t')):
            continue
        opens = raw_line.count('(')
        closes = raw_line.count(')')
        if opens != closes:
            skipped += 1
            continue
        sexpr = _na_parse_sexpr_one(raw_line)
        if not isinstance(sexpr, list) or len(sexpr) < 4 or sexpr[0] != 'neverallow':
            skipped += 1
            continue
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


def  _find_sepinject_blocks(lines: list) -> dict:
    blocks: dict = {}
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        if not _SEPINJECT_HEADER_RE.match(line):
            i += 1
            continue
        block_start = i
        candidate_originals: list = []   
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
        if j >= n:
            i = j
            continue
        live_line = lines[j]
        m_live = _SEPINJECT_LIVE_AUX_NA_RE.match(live_line)
        if not m_live:
            i = block_start + 1
            continue
        aux_name = m_live.group(1)
        live_line_idx = j  
        original_line_no = None
        original_text = None
        for cand_idx, cand_text in candidate_originals:
            if 'sepinject_aux_' not in cand_text:
                original_line_no = cand_idx
                original_text = cand_text
                break
        if original_text is None and candidate_originals:
            original_line_no, original_text = candidate_originals[0]
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


def  _parse_aux_typeattributeset(node) -> tuple:
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


def  _na_sexpr_to_str(node) -> str:
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return '(' + ' '.join(_na_sexpr_to_str(c) for c in node) + ')'
    return ''


def  parse_cil_typeattributesets(cil_path: Path) -> dict:
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
            result[attr_name] = ['or', result[attr_name], expr]
        else:
            result[attr_name] = expr
    return result


def  _na_resolve_set(expr, attr_map: dict, all_types: set, visiting: Optional[set] = None) -> Optional[set]:
    if visiting is None:
        visiting = set()
    if isinstance(expr, str):
        if expr == 'self':
            return {'__SELF__'}
        if expr == 'all':
            return set(all_types)
        if expr in attr_map:
            if expr in visiting:
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


def  collect_all_type_names(cil_path: Path) -> set:
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


def  _augment_attrmap_and_types_with_rules(rules: list,
                                           attr_map: dict,
                                           all_types: set) -> tuple:
    aug_attr_map = dict(attr_map)
    aug_all_types = set(all_types)


    def  add_member(attr_name: str, member: str):
        existing = aug_attr_map.get(attr_name)
        if existing is None:
            aug_attr_map[attr_name] = [member]
        elif isinstance(existing, list):
            if all(isinstance(x, str) for x in existing):
                if member not in existing:
                    aug_attr_map[attr_name] = existing + [member]
            else:
                aug_attr_map[attr_name] = ['or', existing, member]
        else:
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


def  find_neverallow_conflicts(rules: list, cil_paths: list) -> tuple:
    conflicts = []
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
                existing = global_attr_map[attr_name]
                global_attr_map[attr_name] = ['or', existing, expr]
    global_attr_map, global_all_types = _augment_attrmap_and_types_with_rules(
        rules, global_attr_map, global_all_types)


    def  _resolve_prior_exclusions(na: 'CilNeverallow') -> list:
        if not na.previously_rewritten or not na.aux_name:
            return []
        expr = global_attr_map.get(na.aux_name)
        if expr is None:
            return []
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
        for na in neverallows:
            if na.previously_rewritten and not na.prior_excluded_srcs:
                na.prior_excluded_srcs = _resolve_prior_exclusions(na)
        attr_map = global_attr_map
        all_types = global_all_types
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
                if na.previously_rewritten and rule.src in na.prior_excluded_srcs:
                    continue
                key = id(na)
                if key in resolved_cache:
                    src_set, tgt_set = resolved_cache[key]
                else:
                    src_expr_parsed = _na_parse_sexpr_one(na.src_expr)                        if na.src_expr.startswith('(') else na.src_expr
                    tgt_expr_parsed = _na_parse_sexpr_one(na.tgt_expr)                        if na.tgt_expr.startswith('(') else na.tgt_expr
                    src_set = _na_resolve_set(src_expr_parsed, attr_map, all_types)
                    tgt_set = _na_resolve_set(tgt_expr_parsed, attr_map, all_types)
                    resolved_cache[key] = (src_set, tgt_set)
                src_match = (src_set is None) or (rule.src in src_set)
                if rule.tgt == 'self':
                    tgt_match = True
                else:
                    tgt_match = (tgt_set is None) or (rule.tgt in tgt_set)
                if src_match and tgt_match:
                    structural = all(p in na.perms for p in rule.perms) and                                 len(matched) == len(rule.perms)
                    conflicts.append(NeverallowConflict(
                        rule=rule,
                        neverallow=na,
                        matched_perms=matched,
                        structural=structural,
                        src_resolved=src_set,
                    ))
    return conflicts, global_attr_map, global_all_types


def  _make_aux_attr_name(inner_src: str, excluded_srcs) -> str:
    if isinstance(excluded_srcs, str):
        excluded_list = [excluded_srcs]
    else:
        excluded_list = sorted({s for s in excluded_srcs if s})
    norm_inner = re.sub(r'\s+', '', inner_src).strip('()')
    if len(excluded_list) == 1:
        excl_str = re.sub(r'\s+', '', excluded_list[0])
    else:
        excl_str = '_'.join(re.sub(r'\s+', '', s) for s in excluded_list)
    h = hashlib.sha1(f"{norm_inner}~{excl_str}".encode()).hexdigest()[:6]
    safe_inner = re.sub(r'[^a-zA-Z0-9_]+', '_', norm_inner)[:32]
    safe_excl  = re.sub(r'[^a-zA-Z0-9_]+', '_', excl_str)[:24]
    return f"sepinject_aux_{safe_inner}_minus_{safe_excl}_{h}"


def  _format_perms(perms: list) -> str:
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


def  build_rewrite(conflict, aux_registry: dict = None,
                  attr_map: dict = None, all_types: set = None,
                  excluded_srcs: Optional[list] = None,
                  aux_fingerprints: dict = None) -> str:
    na = conflict.neverallow
    if excluded_srcs is None:
        excluded_srcs = [conflict.rule.src]
    excluded_unique = sorted({s for s in excluded_srcs if s})
    if not excluded_unique:
        excluded_unique = []
    src_resolved = getattr(conflict, 'src_resolved', None)
    if src_resolved is None and attr_map is not None and all_types is not None:
        src_parsed = _na_parse_sexpr_one(na.src_expr)            if na.src_expr.lstrip().startswith('(') else na.src_expr
        src_resolved = _na_resolve_set(src_parsed, attr_map, all_types)
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
        excluded_resolved = set(excluded_unique)
    carveout_vacuous = False
    if not excluded_unique:
        carveout_vacuous = True
    elif src_resolved is not None and excluded_resolved is not None:
        if src_resolved.issubset(excluded_resolved):
            carveout_vacuous = True
    else:
        if len(excluded_unique) == 1:
            src_norm = na.src_expr.strip().lstrip('(').rstrip(')').strip()
            excl_norm = excluded_unique[0].strip().lstrip('(').rstrip(')').strip()
            if src_norm == excl_norm:
                carveout_vacuous = True
    if not carveout_vacuous:
        aux_name = _make_aux_attr_name(na.src_expr, excluded_unique)
        if aux_registry is not None and aux_name not in aux_registry:
            inner = na.src_expr if na.src_expr.lstrip().startswith('(')                else f'({na.src_expr})'
            if len(excluded_unique) == 1:
                excl_clause = f'({excluded_unique[0]})'
            else:
                excl_clause = '(' + ' '.join(excluded_unique) + ')'
            aux_registry[aux_name] = (
                f'(typeattribute {aux_name})',
                f'(typeattributeset {aux_name} (and {inner} (not {excl_clause})))',
            )
        if aux_fingerprints is not None:
            fp = (na.tgt_expr, na.cls, tuple(sorted(na.perms)))
            aux_fingerprints.setdefault(aux_name, set()).add(fp)
        return (f"(neverallow {aux_name} {na.tgt_expr} "
                f"({na.cls} {_format_perms(na.perms)}))")
    remaining_perms = [p for p in na.perms if p not in conflict.matched_perms]
    if remaining_perms:
        return (f"(neverallow {na.src_expr} {na.tgt_expr} "
                f"({na.cls} {_format_perms(remaining_perms)}))")
    return (f";; sepinject: cannot rewrite — neverallow source "
            f"({na.src_expr}) resolves entirely to the exempted "
            f"source(s) [{', '.join(excluded_unique) if excluded_unique else '<none>'}] "
            f"and every perm is matched by the proposed allow; "
            f"any rewrite would be vacuous. "
            f"Original allow: {conflict.rule.src} "
            f"{conflict.rule.tgt}:{conflict.rule.cls} "
            f"{ {' '.join(conflict.rule.perms)}} ")


class  RollbackSession:


    def  __init__(self):
        self.session_dir = Path(tempfile.gettempdir()) /            f"sepinject-rollback-{sys.argv[0].split('/')[-1]}-"            f"{os.getpid()}-{int(time.time())}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots: list = []  
        self.committed = False


    def  snapshot(self, path: Path) -> None:
        path = Path(path)
        if not path.exists():
            return
        if any(orig == path for orig, _ in self.snapshots):
            return  
        try:
            abs_path = path.resolve()
            rel_parts = [part.replace(':', '_') for part in abs_path.parts if part not in ('/', '\\')]
            snap = self.session_dir.joinpath(*rel_parts)
        except Exception:
            path_str = str(path)
            safe_path = path_str.lstrip('/').replace(':', '_').replace('..', '_')
            snap = self.session_dir / safe_path
        snap.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, snap)
        self.snapshots.append((path, snap))


    def  revert(self) -> None:
        print(f"\n[!] Reverting {len(self.snapshots)} file(s) from rollback session...")
        for orig, snap in self.snapshots:
            try:
                shutil.copy2(snap, orig)
                print(f"  [-] Restored: {orig}")
            except Exception as e:
                print(f"  [!] Failed to restore {orig}: {e}")
        print(f"[!] Rollback complete. Snapshot dir retained: {self.session_dir}")


    def  commit(self) -> None:
        self.committed = True
        if self.snapshots:
            print(f"\n[*] Pre-run snapshot retained at: {self.session_dir}")
            print(f"    ({len(self.snapshots)} file(s) captured before modification)")


def  prompt_neverallow_conflicts(conflicts: list, binary_findings: list) -> bool:
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
              f"{  {' '.join(rule.perms)} } ;")
        print(f"    Violates:  {na.raw_line.strip()}")
        print(f"    Source:    {na.cil_path}:{na.line_no}")
        print(f"    Matched:   perm(s) {  {' '.join(c.matched_perms)} }  from neverallow")
        if na.previously_rewritten:
            print(f"    State:     existing sepinject carve-out in place")
            print(f"               aux={na.aux_name}")
            print(f"               already excluded: "
                  f"{  {', '.join(na.prior_excluded_srcs)} } ")
            merged_excluded = sorted(set(na.prior_excluded_srcs) | {rule.src})
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
                      f"merged exclusion set: {  {', '.join(merged_excluded)} } )")
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
        carveout_vacuous = False
        if c.src_resolved is not None:
            if c.src_resolved.issubset({rule.src}):
                carveout_vacuous = True
        else:
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
_SEPINJECT_EXTEND_HEADER = ";; sepinject: superseded (extended carve-out below)\n"
_SEPINJECT_AUX_DEPRECATED_HEADER = ";; sepinject: aux decl deprecated (extended below)\n"
_SEPINJECT_VACUITY_BANNER = (
    ";; !!! SEPINJECT VACUITY WARNING !!! "
    "EXTENDING THIS CARVE-OUT WOULD LEAVE THE AUX EMPTY — "
    "REVIEW REQUIRED.\n"
)


def  _prompt_vacuity_decision(na: 'CilNeverallow',
                             new_excluded: list,
                             merged_excluded: list,
                             remaining_perms: list) -> str:
    print("\n" + "!" * 70)
    print(f"[!] VACUITY WARNING: extending existing carve-out would empty it")
    print(f"!" * 70)
    print(f"  Neverallow:         {na.raw_line.strip()}")
    print(f"  File:               {na.cil_path}:{na.line_no}")
    print(f"  Aux attribute:      {na.aux_name}")
    print(f"  Already excluded:   {  {', '.join(na.prior_excluded_srcs)} } ")
    print(f"  Now adding:         {  {', '.join(new_excluded)} } ")
    print(f"  Merged excluded:    {  {', '.join(merged_excluded)} } ")
    print(f"  Original src set:   resolves entirely to the merged exclusion list,")
    print(f"                      so (and (X) (not (merged))) is empty — the")
    print(f"                      neverallow would no longer constrain anything.")
    print()
    print("Options:")
    print("  [e] extend anyway — write empty-aux carve-out (marked with ALL CAPS warning)")
    if remaining_perms:
        print(f"  [p] perm-drop fallback — revert the aux rewrite, drop matched")
        print(f"      perm(s) from the original neverallow instead;")
        print(f"      remaining perms after drop: {  {' '.join(remaining_perms)} } ")
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


def  apply_neverallow_rewrites(conflicts: list, rollback: RollbackSession,
                              all_cil_paths: list | None = None,
                              attr_map: dict | None = None,
                              all_types: set | None = None) -> dict:
    by_file: dict = {}
    for c in conflicts:
        by_file.setdefault(c.neverallow.cil_path, []).append(c)
    aux_registry: dict = {}
    aux_emitted: set = set()  
    aux_fingerprints: dict = {}
    scan_set: set = set()
    if all_cil_paths:
        for entry in all_cil_paths:
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
    vacuity_decisions: dict = {}
    extend_group_keys: dict = {}  
    for c in conflicts:
        if c.neverallow.previously_rewritten:
            key = (c.neverallow.cil_path, c.neverallow.line_no)
            extend_group_keys.setdefault(key, []).append(c)
    for (cil_path_k, line_no_k), group in extend_group_keys.items():
        na = group[0].neverallow
        new_excluded = sorted({c.rule.src for c in group if c.rule.src})
        merged_excluded = sorted(set(na.prior_excluded_srcs) | set(new_excluded))
        merged_matched = sorted({p for c in group for p in c.matched_perms})
        src_resolved = group[0].src_resolved
        vacuous = False
        if src_resolved is not None:
            if src_resolved.issubset(set(merged_excluded)):
                vacuous = True
        else:
            src_norm = na.src_expr.strip().lstrip('(').rstrip(')').strip()
            if len(merged_excluded) == 1 and src_norm == merged_excluded[0]:
                vacuous = True
        if vacuous:
            remaining_perms = [p for p in na.perms if p not in merged_matched]
            decision = _prompt_vacuity_decision(
                na, new_excluded, merged_excluded, remaining_perms)
            for c in group:
                vacuity_decisions[id(c)] = decision
    deprecated_auxes: set = set()
    for (_, _), group in extend_group_keys.items():
        decision = vacuity_decisions.get(id(group[0]), 'extend')
        if decision in ('extend',) or decision not in ('skip', 'permdrop'):
            na = group[0].neverallow
            if na.aux_name:
                deprecated_auxes.add(na.aux_name)
        elif decision == 'permdrop':
            na = group[0].neverallow
            if na.aux_name:
                deprecated_auxes.add(na.aux_name)
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
        line_conflicts: dict = {}
        for c in file_conflicts:
            line_conflicts.setdefault(c.neverallow.line_no, []).append(c)
        new_lines = []
        modified = 0
        for idx, raw_line in enumerate(lines, start=1):
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
            base_na = cs[0].neverallow
            is_extend = base_na.previously_rewritten
            decision = vacuity_decisions.get(id(cs[0])) if is_extend else None
            if decision == 'skip':
                new_lines.append(_SEPINJECT_VACUITY_BANNER)
                new_lines.append(
                    f";; sepinject: SKIPPED extend for {  "
                    f"{', '.join(sorted({c.rule.src for c in cs if c.rule.src}))}"
                    f" }  — would have produced empty carve-out\n"
                )
                new_lines.append(raw_line)
                continue
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
                new_lines.append(_SEPINJECT_EXTEND_HEADER)
                new_lines.append(
                    f";; sepinject: prior aux: {base_na.aux_name}\n"
                )
                new_lines.append(
                    f";; sepinject: prior exclusions: "
                    f"{  {', '.join(base_na.prior_excluded_srcs)} } \n"
                )
                new_lines.append(
                    f";; sepinject: now adding: "
                    f"{  {', '.join(sorted(excluded_srcs_set))} } \n"
                )
                new_lines.append(f";; {stripped_nl}{line_ending}")
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
                        f"allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} "
                        for r in triggering_rules
                    )
                    new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
                    new_lines.append(pd_line + line_ending)
                    modified += 1
                    continue
                merged_excluded = sorted(
                    set(base_na.prior_excluded_srcs) | excluded_srcs_set
                )
                merged_conflict = NeverallowConflict(
                    rule=cs[0].rule,
                    neverallow=base_na,
                    matched_perms=sorted(merged_matched),
                    structural=structural_any,
                    src_resolved=cs[0].src_resolved,
                )
                if decision == 'extend':
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
                    f"allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} "
                    for r in triggering_rules
                )
                new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
                new_lines.append(rewrite + line_ending)
                modified += 1
                continue
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
                f"allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} "
                for r in triggering_rules
            )
            new_lines.append(f";; sepinject: triggered by: {trigger_summary}\n")
            new_lines.append(rewrite + line_ending)
            modified += 1
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
    reused = {n: fps for n, fps in aux_fingerprints.items() if len(fps) > 1}
    if reused:
        print(f"\n[!] {len(reused)} sepinject_aux_* attribute(s) reused across "
              f"substantively different rewrites:")
        for aux_name in sorted(reused):
            fps = reused[aux_name]
            print(f"  - {aux_name} used by {len(fps)} rewrite(s):")
            for tgt, cls, perms in sorted(fps):
                print(f"      tgt={tgt}  class={cls}  perms={  {' '.join(perms)} } ")
        print(f"  Sharing is correct, but a malformed aux would break "
              f"every neverallow that references it — review the "
              f"(typeattributeset ...) bodies above carefully.")
    return results
@dataclass


class  CilMlsconstrain:
    cil_path: Path
    line_no: int            
    raw_line: str           
    cls: str                
    perms: list             
    expr_text: str          
    previously_rewritten: bool = False
    aux_name: Optional[str] = None            
    prior_exempted_srcs: list = field(default_factory=list)  
    triggers_text: Optional[str] = None       
    original_line_no: Optional[int] = None    
@dataclass


class  MlsconstrainConflict:
    rule: 'TeRule'                   
    mlsconstrain: CilMlsconstrain    
    matched_perms: list              
    verdict: str                     
_SEPINJECT_MLS_HEADER_RE = re.compile(
    r'^\s*;;\s*sepinject:\s*commented\s*\(mlsconstrain rewritten below\)',
)
_SEPINJECT_MLS_ORIG_RE = re.compile(
    r'^\s*;;\s*(\(mlsconstrain\b.*\))\s*$',
)
_SEPINJECT_MLS_LIVE_RE = re.compile(
    r'\(\s*eq\s+t1\s+(sepinject_mlsaux_[A-Za-z0-9_]+)\s*\)'
)
_SEPINJECT_MLS_COMMENTED_HDR = ";; sepinject: commented (mlsconstrain rewritten below)\n"
_SEPINJECT_MLS_EXTEND_HEADER  = ";; sepinject: mls superseded (extended exemption below)\n"


def  _split_mls_classperms(node):
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


def  _strip_mls_exemption(expr_node):
    if not (isinstance(expr_node, list) and len(expr_node) >= 3
            and expr_node[0] == 'or'):
        return (expr_node, None)
    last = expr_node[-1]
    if (isinstance(last, list) and len(last) == 3 and last[0] == 'eq'
            and last[1] == 't1' and isinstance(last[2], str)
            and last[2].startswith('sepinject_mlsaux_')):
        aux_name = last[2]
        rest = expr_node[1:-1]
        orig = rest[0] if len(rest) == 1 else (['or'] + rest)
        return (orig, aux_name)
    return (expr_node, None)


def  parse_cil_mlsconstrains(cil_path: Path) -> list:
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
        prev = False
        aux_name = None
        if _SEPINJECT_MLS_LIVE_RE.search(raw_line):
            orig_node, aux_name = _strip_mls_exemption(expr_node)
            if aux_name is not None:
                prev = True
                expr_node = orig_node
        triggers_text = None
        original_line_no = None
        if prev:
            trig_bits = []
            j = idx - 2  
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
_MLS_LEVEL_KW    = {'l1', 'l2', 'h1', 'h2'}
_MLS_ROLEUSER_KW = {'r1', 'r2', 'u1', 'u2'}
_MLS_TYPE_KW     = {'t1', 't2'}
_MLS_REL_OPS     = {'eq', 'neq', 'dom', 'domby', 'incomp', 'dominates'}
_KLEENE_NOT = {'T': 'F', 'F': 'T', 'U': 'U'}


def  _mls_member(concrete_type: str, name: str,
                attr_map: dict, all_types: set) -> str:
    if name == concrete_type:
        return 'T'
    parsed = _na_parse_sexpr_one(name) if name.lstrip().startswith('(') else name
    s = _na_resolve_set(parsed, attr_map, all_types)
    if s is None:
        return 'U'
    return 'T' if concrete_type in s else 'F'


def  _mls_eval_leaf(op: str, a, b, subj: str, tgt: str,
                   attr_map: dict, all_types: set) -> str:
    if not (isinstance(a, str) and isinstance(b, str)):
        return 'U'
    if op not in ('eq', 'neq'):
        return 'U'
    a_is_t = a in _MLS_TYPE_KW
    b_is_t = b in _MLS_TYPE_KW
    a_is_runtime = a in _MLS_LEVEL_KW or a in _MLS_ROLEUSER_KW
    b_is_runtime = b in _MLS_LEVEL_KW or b in _MLS_ROLEUSER_KW


    def  concrete(kw):
        return subj if kw == 't1' else tgt
    if a_is_t and b_is_t:
        res = 'T' if concrete(a) == concrete(b) else 'F'
    elif a_is_t and not (b_is_t or b_is_runtime):
        res = _mls_member(concrete(a), b, attr_map, all_types)
    elif b_is_t and not (a_is_t or a_is_runtime):
        res = _mls_member(concrete(b), a, attr_map, all_types)
    else:
        return 'U'
    return _KLEENE_NOT[res] if op == 'neq' else res


def  _mls_eval(expr, subj: str, tgt: str,
              attr_map: dict, all_types: set) -> str:
    if isinstance(expr, str):
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
    return 'U'


def  find_mlsconstrain_conflicts(rules: list, cil_paths: list) -> tuple:
    conflicts = []
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


    def  _resolve_prior_exemptions(mc: 'CilMlsconstrain') -> list:
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
                if mc.previously_rewritten and rule.src in mc.prior_exempted_srcs:
                    continue
                tgt = rule.src if rule.tgt == 'self' else rule.tgt
                key = (id(mc), rule.src, tgt)
                if key in expr_cache:
                    verdict3 = expr_cache[key]
                else:
                    parsed = _na_parse_sexpr_one(mc.expr_text)                        if mc.expr_text.lstrip().startswith('(') else mc.expr_text
                    verdict3 = _mls_eval(parsed, rule.src, tgt, attr_map, all_types)
                    expr_cache[key] = verdict3
                if verdict3 == 'T':
                    continue
                conflicts.append(MlsconstrainConflict(
                    rule=rule,
                    mlsconstrain=mc,
                    matched_perms=matched,
                    verdict='blocked' if verdict3 == 'F' else 'maybe',
                ))
    return conflicts, global_attr_map, global_all_types


def  _make_mls_aux_attr_name(exempted_srcs) -> str:
    if isinstance(exempted_srcs, str):
        excl = [exempted_srcs]
    else:
        excl = sorted({s for s in exempted_srcs if s})
    excl_str = '_'.join(re.sub(r'\s+', '', s) for s in excl)
    h = hashlib.sha1(excl_str.encode()).hexdigest()[:6]
    safe = re.sub(r'[^A-Za-z0-9_]+', '_', excl_str)[:40]
    return f"sepinject_mlsaux_{safe}_{h}"


def  build_mls_rewrite(conflict, aux_registry: dict = None,
                      exempted_srcs: Optional[list] = None) -> str:
    mc = conflict.mlsconstrain
    if exempted_srcs is None:
        exempted_srcs = [conflict.rule.src]
    excl = sorted({s for s in exempted_srcs if s})
    if not excl:
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


def  prompt_mlsconstrain_conflicts(conflicts: list) -> bool:
    print("\n" + "=" * 70)
    print(f"[!] {len(conflicts)} mlsconstrain conflict(s) detected in CIL source")
    print("=" * 70)
    for i, c in enumerate(conflicts, 1):
        rule = c.rule
        mc = c.mlsconstrain
        print(f"\n  Conflict {i}:")
        print(f"    Adding:    allow {rule.src} {rule.tgt}:{rule.cls} "
              f"{  {' '.join(rule.perms)} } ;")
        print(f"    Constraint:(mlsconstrain ({mc.cls} "
              f"{  {' '.join(mc.perms)} } ) {mc.expr_text})")
        print(f"    Source:    {mc.cil_path}:{mc.line_no}")
        print(f"    Matched:   perm(s) {  {' '.join(c.matched_perms)} } ")
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
                  f"{  {', '.join(mc.prior_exempted_srcs)} } ")
            print(f"    Rewrite:   (will EXTEND exemption — merged set: "
                  f"{  {', '.join(merged)} } )")
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


def  apply_mlsconstrain_rewrites(conflicts: list, rollback: RollbackSession,
                                all_cil_paths: list | None = None,
                                attr_map: dict | None = None,
                                all_types: set | None = None) -> dict:
    by_file: dict = {}
    for c in conflicts:
        by_file.setdefault(c.mlsconstrain.cil_path, []).append(c)
    aux_registry: dict = {}
    aux_emitted: set = set()
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
            new_srcs = sorted({c.rule.src for c in cs if c.rule.src})
            triggering_rules = [c.rule for c in cs]
            trigger_summary = ', '.join(
                f"allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} "
                for r in triggering_rules
            )
            if is_extend:
                merged_excluded = sorted(set(base_mc.prior_exempted_srcs)
                                         | set(new_srcs))
                new_lines.append(_SEPINJECT_MLS_EXTEND_HEADER)
                new_lines.append(f";; sepinject: prior mlsaux: {base_mc.aux_name}\n")
                new_lines.append(
                    f";; sepinject: prior exemptions: "
                    f"{  {', '.join(base_mc.prior_exempted_srcs)} } \n")
                new_lines.append(
                    f";; sepinject: now adding: {  {', '.join(new_srcs)} } \n")
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
@dataclass


class  ValidateIssue:
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
_TRIGGER_RULE_RE = re.compile(
    r'allow\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+):([A-Za-z0-9_]+)\s+'
    r'[{(]\s*([A-Za-z0-9_\s]+?)\s*[})]',
)


def  _parse_triggers_text(text: Optional[str]) -> list:
    if not text:
        return []
    out = []
    for m in _TRIGGER_RULE_RE.finditer(text):
        src, tgt, cls, perms_str = m.groups()
        perms = perms_str.split()
        out.append(TeRule(op='allow', src=src, tgt=tgt, cls=cls, perms=perms))
    return out


def  scan_validate_issues(cil_paths: list,
                         attr_map: Optional[dict] = None,
                         all_types: Optional[set] = None,
                         full_rebuild: bool = False) -> list:
    issues: list = []
    norm_paths = []
    for entry in cil_paths:
        if isinstance(entry, tuple):
            norm_paths.append(entry)
        else:
            norm_paths.append((entry.name, entry))
    all_aux_decls: dict = {}     
    all_aux_sets: dict = {}      
    all_live_aux_refs: dict = {} 
    all_blocks_by_file: dict = {}  
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
        blocks = _find_sepinject_blocks(lines)
        all_blocks_by_file[cil_path] = blocks
        for live_ln, info in blocks.items():
            aux = info['aux_name']
            raw = lines[live_ln - 1]
            all_live_aux_refs.setdefault(aux, []).append((cil_path, live_ln, raw))
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
                aux_name = m_tas.group(1)
                sexpr = _na_parse_sexpr_one(raw)
                body_node = None
                if (isinstance(sexpr, list) and len(sexpr) >= 3
                        and sexpr[0] == 'typeattributeset'):
                    body_node = sexpr[2]
                all_aux_sets.setdefault(aux_name, []).append(
                    (cil_path, idx, raw, body_node))
    for label, cil_path in norm_paths:
        if not cil_path or not cil_path.exists():
            continue
        blocks = all_blocks_by_file.get(cil_path, {})
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
        if full_rebuild:
            for live_ln, info in blocks.items():
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


    def  _node_refs_sepinject_aux(node) -> Optional[str]:
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
                nested = _node_refs_sepinject_aux(body)
            else:
                inner_node = _na_parse_sexpr_one(inner_text)                    if inner_text.startswith('(') else inner_text
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
    for aux_name, refs in all_live_aux_refs.items():
        if aux_name not in all_aux_sets:
            for cil_path, line_no, raw in refs:
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
    if attr_map is not None and all_types is not None:
        for aux_name, occurrences in all_aux_sets.items():
            for cil_path, line_no, raw, body in occurrences:
                if body is None:
                    continue
                inner_text, excl = _parse_aux_typeattributeset(body)
                if inner_text is None or excl is None:
                    continue
                inner_node = _na_parse_sexpr_one(inner_text)                    if inner_text.startswith('(') else inner_text
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
                            f"{  {', '.join(sorted(resolved))} }  ⊆ "
                            f"excluded {  {', '.join(excl)} } ) — "
                            f"the neverallow constrains nothing"
                        ),
                        aux_name=aux_name,
                        repairable=True,
                    ))
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


def  make_validate_backup(rom_root: Path, cil_paths: list) -> Path:
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
            rel = Path('external') / p.name
        dest = backup_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        n += 1
    print(f"  [+] Backed up {n} file(s) to: {backup_dir}")
    return backup_dir


def  _group_blocks_by_original(blocks_per_file: dict) -> dict:
    groups: dict = {}
    for cil_path, blocks in blocks_per_file.items():
        for live_ln, info in blocks.items():
            orig = info.get('original_text')
            if not orig:
                continue
            key = (cil_path, ' '.join(orig.split()))  
            if key not in groups:
                groups[key] = {
                    'original_text': orig,
                    'cil_path':      cil_path,
                    'blocks':        [],
                    'triggers':      [],
                }
            groups[key]['blocks'].append({'live_line_no': live_ln, **info})
            groups[key]['triggers'].extend(_parse_triggers_text(info.get('triggers_text')))
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


def  validate_policy(rom_root: Path,
                    cil_paths: list,
                    full_rebuild: bool = False,
                    dry_run: bool = False) -> int:
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
    issues = scan_validate_issues(cil_paths, attr_map=attr_map,
                                  all_types=all_types,
                                  full_rebuild=full_rebuild)
    if not issues:
        print("[OK] No issues detected.  Policy is clean.")
        return 0
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
    aux_cleanup_targets: dict = {}  
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
    if not dry_run:
        try:
            make_validate_backup(rom_root, cil_paths)
        except OSError as e:
            print(f"[!] Backup failed: {e}.  Aborting.")
            return 1
    rollback = RollbackSession()
    if dry_run:
        for (cp, _), g in groups.items():
            print(f"\n  Would rebuild in {cp.name}: {g['original_text']}")
            print(f"    Triggers ({len(g['triggers'])}):")
            for r in g['triggers']:
                print(f"      allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} ")
            print(f"    Blocks involved: {len(g['blocks'])}")
        for cp, names in aux_cleanup_targets.items():
            print(f"\n  Would clean up in {cp.name}: {sorted(names)}")
        print("\n[*] Dry-run complete.  Re-run without --dry-run to apply.")
        return 0
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
    aux_refs: dict = {}   
    aux_locations: dict = {}  
    aux_set_lines_by_file: dict = {}  
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


                    def  _collect(node):
                        if isinstance(node, str):
                            if node.startswith('sepinject_aux_'):
                                refs.add(node)
                            return
                        if isinstance(node, list):
                            for c in node:
                                _collect(c)
                    _collect(sexpr[2])
                refs.discard(aux_name)  
                aux_refs[aux_name] = refs
                aux_set_lines_by_file[p][aux_name] = sexpr[2] if (
                    isinstance(sexpr, list) and len(sexpr) >= 3) else None
    flagged: set = set()
    for s in auxes_to_comment_per_file.values():
        flagged.update(s)
    reverse_refs: dict = {}
    for src, dests in aux_refs.items():
        for d in dests:
            reverse_refs.setdefault(d, set()).add(src)
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
            if aux_name in block_aux_names:
                continue  
            referrers = reverse_refs.get(aux_name, set())
            external_refs = referrers - flagged
            if not external_refs:
                flagged.add(aux_name)
                changed = True
    for aux_name in flagged:
        for cp, body_map in aux_set_lines_by_file.items():
            if aux_name in body_map or aux_name in [
                a for (path, _ln) in aux_locations.get(aux_name, [])
                if path == cp for a in [aux_name]
            ]:
                auxes_to_comment_per_file.setdefault(cp, set()).add(aux_name)
                files_to_modify.add(cp)
    aux_registry: dict = {}
    aux_emitted: set = set()
    aux_fingerprints: dict = {}
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
    plans_per_file: dict = {}  
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
        src_resolved = _na_resolve_set(src_node, attr_map, all_types)
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
            for b in g['blocks']:
                plans_per_file.setdefault(cp, []).append(
                    (b['live_line_no'], None, orig_text))
            continue
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
            f"allow {r.src} {r.tgt}:{r.cls} { {' '.join(r.perms)}} "
            for r in triggering_rules_kept
        )
        for b in g['blocks']:
            plans_per_file.setdefault(cp, []).append(
                (b['live_line_no'], rewrite, triggers_summary))
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
                    out.append(';; sepinject: VALIDATE — broken block removed; original restored\n')
                    out.append(';; ' + raw)
                    out.append(f"{extra}{line_ending}")
                else:
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
REBUILD_MODS_MARKER_DEFAULT = '; ~~~:BEGIN_MODS:~~~'
_REBUILD_ALLOW_RE = re.compile(
    r'^\s*\(\s*allow\s+'
    r'(\S+)\s+'                
    r'(\S+)\s+'                
    r'\(\s*(\S+)\s+'           
    r'\(\s*([^)]*?)\s*\)\s*\)' 
    r'\s*\)\s*$'
)


def  parse_cil_mods_allow_rules(cil_path: Path,
                               marker: str = REBUILD_MODS_MARKER_DEFAULT) -> list:
    if not cil_path.exists():
        return []
    text = cil_path.read_text(errors='replace')
    lines = text.splitlines()
    marker_norm = marker.strip()
    mods_start: Optional[int] = None
    for i, ln in enumerate(lines):
        if ln.strip() == marker_norm:
            mods_start = i + 1   
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
        if not stripped.startswith('(allow'):
            continue
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


def  find_rom_sepolicy_cils(rom_root: Path, plat_only: bool = False) -> list:
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
        ppv = vnd_sel / 'plat_pub_versioned.cil'
        if ppv.exists():
            out.append(('plat_pub_versioned', ppv))
    return out


def  make_rebuild_neverallows_backup(rom_root: Path, cil_paths: list) -> Path:
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


def  rebuild_neverallows(rom_root: Path,
                        dry_run: bool = False,
                        skip_sha256: bool = False,
                        plat_only: bool = False,
                        assume_yes: bool = False,
                        marker: str = REBUILD_MODS_MARKER_DEFAULT) -> int:
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
    print("\n[*] Scanning CIL files for neverallow conflicts")
    conflicts, na_attr_map, na_all_types = find_neverallow_conflicts(
        all_rules, cil_paths)
    if not conflicts:
        print("\n[OK] No neverallow conflicts detected — sepolicy is already clean "
              "with respect to the mods below the marker.")
        return 0
    print(f"\n[!] {len(conflicts)} neverallow conflict(s) found")
    if dry_run:
        print("\n--- Dry-run preview (no files will be written) ---")
        for i, c in enumerate(conflicts, 1):
            rule = c.rule
            na = c.neverallow
            print(f"\n  Conflict {i}:")
            print(f"    Mod allow: allow {rule.src} {rule.tgt}:{rule.cls} "
                  f"{  {' '.join(rule.perms)} } ;")
            print(f"    Violates:  {na.raw_line.strip()}")
            print(f"    Source:    {na.cil_path}:{na.line_no}")
            print(f"    Matched:   perm(s) {  {' '.join(c.matched_perms)} } ")
            try:
                print(f"    Proposed:  {build_rewrite(c)}")
            except Exception as e:
                print(f"    Proposed:  (rewrite preview failed: {e})")
        print("\n[OK] Dry-run complete — re-run without --dry-run to apply.")
        return 0
    if assume_yes:
        print("\n[*] --yes/--assume-yes was passed — skipping confirmation prompt.")
        proceed = True
    else:
        proceed = prompt_neverallow_conflicts(conflicts, binary_findings=[])
    if not proceed:
        print("\n[!] User declined — no files modified.")
        return 2
    print("\n[*] Backing up CIL files before modification")
    try:
        make_rebuild_neverallows_backup(rom_root, cil_paths)
    except OSError as e:
        print(f"[!] Backup failed: {e} — aborting before any modification.")
        return 1
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


def  make_recreate_mlsconstrains_backup(rom_root: Path, cil_paths: list) -> Path:
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


def  recreate_mlsconstrains(rom_root: Path,
                           dry_run: bool = False,
                           skip_sha256: bool = False,
                           plat_only: bool = False,
                           assume_yes: bool = False,
                           marker: str = REBUILD_MODS_MARKER_DEFAULT,
                           only_domain: Optional[str] = None) -> int:
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
    print("\n[*] Scanning CIL files for mlsconstrain conflicts")
    conflicts, mc_attr_map, mc_all_types = find_mlsconstrain_conflicts(
        all_rules, cil_paths)
    if not conflicts:
        print("\n[OK] No mlsconstrain conflicts detected — every mod allow is "
              "already permitted by the MLS constraints (via type clauses).")
        return 0
    print(f"\n[!] {len(conflicts)} mlsconstrain conflict(s) found")
    if dry_run:
        print("\n--- Dry-run preview (no files will be written) ---")
        for i, c in enumerate(conflicts, 1):
            rule = c.rule
            mc = c.mlsconstrain
            print(f"\n  Conflict {i}:")
            print(f"    Mod allow: allow {rule.src} {rule.tgt}:{rule.cls} "
                  f"{  {' '.join(rule.perms)} } ;")
            print(f"    Constraint:(mlsconstrain ({mc.cls} "
                  f"{  {' '.join(mc.perms)} } ) {mc.expr_text})")
            print(f"    Source:    {mc.cil_path}:{mc.line_no}")
            print(f"    Matched:   perm(s) {  {' '.join(c.matched_perms)} } ")
            print(f"    Verdict:   {c.verdict}")
            try:
                print(f"    Proposed:  {build_mls_rewrite(c)}")
            except Exception as e:
                print(f"    Proposed:  (rewrite preview failed: {e})")
        print("\n[OK] Dry-run complete — re-run without --dry-run to apply.")
        return 0
    if assume_yes:
        print("\n[*] --yes/--assume-yes was passed — skipping confirmation prompt.")
        proceed = True
    else:
        proceed = prompt_mlsconstrain_conflicts(conflicts)
    if not proceed:
        print("\n[!] User declined — no files modified.")
        return 2
    print("\n[*] Backing up CIL files before modification")
    try:
        make_recreate_mlsconstrains_backup(rom_root, cil_paths)
    except OSError as e:
        print(f"[!] Backup failed: {e} — aborting before any modification.")
        return 1
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


def  scan_binary_neverallows(helper: Path, policies: list) -> list:
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
CACHE_DIR = Path.home() / '.cache' / 'sepinject'
HELPER_NAME = 'sepatch_helper'
LIBSEPOL_SOURCE_URL = "https://github.com/SELinuxProject/selinux/releases/download/3.7/libsepol-3.7.tar.gz"
LIBSEPOL_SOURCE_SHA256 = "7619b3b9483879bc8e9312da75d5c5e3f5e380fddd3fd73f3f2ccd7dc55b609b"


def  _source_hash() -> str:
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


def  _run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def  _pkg_config(*args) -> Optional[str]:
    try:
        r = _run(['pkg-config'] + list(args))
        return r.stdout.strip() if r.returncode == 0 else None
    except FileNotFoundError:
        return None


def  _find_headers() -> Optional[str]:
    cflags = _pkg_config('--cflags', 'libsepol')
    if cflags is not None:
        return cflags  
    for d in ['/usr/include', '/usr/local/include']:
        if Path(d, 'sepol', 'policydb', 'policydb.h').exists():
            return f'-I{d}'
    return None  


def  _probe_link_args(src: Path, helper: Path) -> Optional[list[str]]:
    include_flag = _find_headers() or ''


    def  try_compile(link_flags: list[str], label: str) -> bool:
        cmd = ['gcc', '-O2', '-Wno-unused-result',
               '-o', str(helper), str(src)] +              ([include_flag] if include_flag else []) +              link_flags
        r = _run(cmd)
        if r.returncode == 0:
            print(f"  [+] Linked with: {label}")
            if r.stderr.strip():
                print(f"  [~] {r.stderr.strip()}")
            return True
        return False
    import glob
    pc_static = _pkg_config('--static', '--libs', 'libsepol')
    if pc_static:
        pc_libdir = _pkg_config('--variable=libdir', 'libsepol') or ''
        if pc_libdir:
            a = Path(pc_libdir) / 'libsepol.a'
            if a.exists() and try_compile([str(a)], f'static {a}'):
                return [str(a)]
            flags = ['-Wl,--whole-archive', str(a), '-Wl,--no-whole-archive']
            if a.exists() and try_compile(flags, f'whole-archive {a}'):
                return flags
    static_candidates = (
        glob.glob('/usr/lib/libsepol.a') +
        glob.glob('/usr/local/lib/libsepol.a') +
        glob.glob('/usr/lib/*/libsepol.a') +        
        glob.glob('/usr/lib64/libsepol.a') +         
        glob.glob('/usr/lib32/libsepol.a')
    )
    for a in static_candidates:
        if not Path(a).exists():
            continue
        if try_compile([a], f'static {a}'):
            return [a]
        flags = ['-Wl,--whole-archive', a, '-Wl,--no-whole-archive']
        if try_compile(flags, f'whole-archive {a}'):
            return flags
    libdirs = []
    pc_libdir = _pkg_config('--variable=libdir', 'libsepol')
    if pc_libdir:
        libdirs = [f'-L{pc_libdir}']
    if try_compile(libdirs + ['-lsepol'], 'dynamic -lsepol'):
        return libdirs + ['-lsepol']
    pc_libs = _pkg_config('--libs', 'libsepol')
    if pc_libs:
        flags = pc_libs.split()
        if try_compile(flags, f'pkg-config: {pc_libs}'):
            return flags
    return None


def  _build_libsepol_from_source() -> Optional[tuple[str, str]]:
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
    sha = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if sha != LIBSEPOL_SOURCE_SHA256:
        print(f"  [!] Checksum mismatch: got {sha}")
        return None
    print("  [*] Extracting…")
    build_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball) as tf:
        tf.extractall(build_dir)
    src_dir = next(build_dir.iterdir())  
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


def  get_or_compile_helper() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    helper = CACHE_DIR / f'{HELPER_NAME}_{_source_hash()}'
    if helper.exists():
        return helper
    print("[*] Compiling C policy helper (first run)…")
    src = CACHE_DIR / 'sepatch_helper.c'
    src.write_text(HELPER_C_SOURCE)
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
    helper.chmod(0o755)
    return helper


def  patch_policy(helper: Path, rules_json: str, policy_path: Path) -> bool:
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


def  remove_rules_to_cil(rules: list[RemoveRule]) -> list[str]:
    targets = []
    for r in rules:
        if r.op == 'remove_allow':
            perms = ' '.join(r.perms)
            targets.append(f'(allow {r.src} {r.tgt} ({r.cls} ({perms})))')
        elif r.op == 'remove_genfscon':
            targets.append(f'(genfscon {r.src} "{r.tgt}"')  
        elif r.op == 'remove_permissive':
            targets.append(f'(typepermissive {r.type_name})')
        elif r.op == 'remove_type':
            targets.append(f'(type {r.type_name})')
            targets.append(f'(roletype object_r {r.type_name})')
            targets.append(f'({r.type_name})')  
        elif r.op == 'remove_typeattribute':
            targets.append(f'(typeattributeset {r.attr} ({r.type_name}))')
    return targets


def  remove_from_cil(cil_path: Path, remove_rules: list[RemoveRule]) -> bool:
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
    exact_targets: set[str] = set()
    prefix_targets: list[str] = []
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
        if stripped in exact_targets:
            print(f"  [-] Removed: {stripped}")
            removed += 1
            continue
        matched_prefix = False
        for pfx in prefix_targets:
            if stripped.startswith(pfx):
                print(f"  [-] Removed (prefix match): {stripped}")
                removed += 1
                matched_prefix = True
                break
        if matched_prefix:
            continue
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


def  rules_to_cil(rules: list[TeRule]) -> str:
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
            lines.append(f'(type {r.type_name})')
            lines.append(f'(roletype object_r {r.type_name})')
            if r.attr:
                lines.append(f'(typeattributeset {r.attr} ({r.type_name}))')
        elif r.op == 'attribute':
            lines.append(f'(typeattribute {r.type_name})')
        elif r.op == 'typeattribute':
            lines.append(f'(typeattributeset {r.attr} ({r.type_name}))')
        elif r.op == 'type_transition':
            if r.tr_name:
                lines.append(
                    f'(typetransition {r.src} {r.tgt} {r.cls} "{r.tr_name}" {r.default})'
                )
            else:
                lines.append(f'(typetransition {r.src} {r.tgt} {r.cls} {r.default})')
        elif r.op == 'genfscon':
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
_DOMAIN_ATTRS = {'domain', 'coredomain'}
_CORE_ATTRIBUTE = 'coredomain'


def  detect_new_domains(rules: list) -> set[str]:
    domains: set[str] = set()
    for r in rules:
        if r.op == 'type' and r.attr in _DOMAIN_ATTRS:
            domains.add(r.type_name)
        elif r.op == 'typeattribute' and r.attr in _DOMAIN_ATTRS:
            domains.add(r.type_name)
        elif r.op == 'type_transition' and r.cls == 'process':
            domains.add(r.default)
    return domains


def  synthesize_coredomain_rules(domains: set[str], existing_rules: list,
                                cil_paths: list | None = None) -> list:
    if not domains:
        return []
    already_attributed: set[str] = set()
    for r in existing_rules:
        if r.op == 'typeattribute' and r.attr == _CORE_ATTRIBUTE:
            already_attributed.add(r.type_name)
    if cil_paths:
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


def  augment_typeattributeset_in_cil(cil_path: Path, attr_name: str,
                                     types_to_add: list[str]) -> bool:
    if not cil_path.exists():
        print(f"  [!] CIL file not found, skipping: {cil_path}")
        return False
    if not types_to_add:
        return True
    text = cil_path.read_text(errors='replace')
    backup = cil_path.with_suffix(cil_path.suffix + '.bak')
    if not backup.exists():
        shutil.copy2(cil_path, backup)
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
        replacement = f'(typeattributeset {attr_name} ({" ".join(combined)}))'
        new_text = text[:m.start()] + replacement + text[m.end():]
        cil_path.write_text(new_text)
        print(f"  [+] Extended (typeattributeset {attr_name} ...) in {cil_path.name} "
              f"with: {' '.join(new_members)}")
        return True
    new_block = f'\n(typeattributeset {attr_name} ({" ".join(types_to_add)}))\n'
    with open(cil_path, 'a') as f:
        f.write(new_block)
    print(f"  [+] Added new (typeattributeset {attr_name} ...) to {cil_path.name}")
    return True


def  patch_vendor_cil_augmentations(vendor_cil_path: Path,
                                    augmentations: dict[str, list[str]]) -> bool:
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


def  patch_cil(cil_path: Path, rules: list[TeRule]) -> bool:
    if not cil_path.exists():
        print(f"  [!] CIL file not found, skipping: {cil_path}")
        return False
    print(f"\n[*] Patching CIL: {cil_path}")
    existing = cil_path.read_text(errors='replace')
    backup = cil_path.with_suffix('.cil.bak')
    if not backup.exists():
        shutil.copy2(cil_path, backup)
        print(f"  [+] Backup: {backup}")
    cil_block = rules_to_cil(rules)
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


def  _api_version_from_vers_file(selinux_dir: Path) -> Optional[str]:
    mapping_dir = selinux_dir / 'mapping'
    if not mapping_dir.is_dir():
        return None
    import re as _re
    candidates = []
    for f in mapping_dir.glob('*.cil'):
        m = _re.match(r'(\d+)\.0\.cil$', f.name)
        if m:
            candidates.append((int(m.group(1)), f))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1].name  


def  compute_plat_hash(selinux_dir: Path, policy_cil_name: str = 'plat_sepolicy.cil') -> str:
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


def  update_sha256(selinux_dir: Path, vendor_selinux_dir: Optional[Path],
                  system_ext_selinux_dir: Optional[Path] = None) -> bool:
    sha_file = selinux_dir / 'plat_sepolicy_and_mapping.sha256'
    if not sha_file.exists():
        print(f"  [!] SHA256 file not found, skipping: {sha_file}")
        return False
    print(f"\n[*] Recomputing SHA-256 sidecars")
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


def  patch_seapp_contexts(seapp_path: Path, seapp_entries: list[str]) -> bool:
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


def  remove_seapp_contexts(seapp_path: Path, entries_to_remove: list[str]) -> bool:
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


def  parse_seapp_file(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


def  patch_file_contexts(file_ctx_path: Path, file_ctx_entries: list[str]) -> bool:
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


def  parse_file_contexts_file(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


def  patch_property_contexts(prop_ctx_path: Path, entries: list[str]) -> bool:
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


def  parse_property_contexts_file(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


def  patch_service_contexts(svc_ctx_path: Path, entries: list[str]) -> bool:
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


def  parse_service_contexts_file(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines


def  patch_hwservice_contexts(hwsvc_ctx_path: Path, entries: list[str]) -> bool:
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


def  parse_hwservice_contexts_file(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            lines.append(line)
    return lines
ROM_POLICY_CANDIDATES = [
    'vendor_boot/cpio_tree/sepolicy',
    'vendor/fs_tree/etc/selinux/precompiled_sepolicy',
    'system/fs_tree/system/etc/selinux/precompiled_sepolicy',
]
ROM_SYSTEM_SELINUX = 'system/fs_tree/system/etc/selinux'
ROM_SYSTEM_EXT_SELINUX = 'system_ext/fs_tree/etc/selinux'
ROM_VENDOR_SELINUX = 'vendor/fs_tree/etc/selinux'
PLAT_PROPERTY_CONTEXTS  = 'plat_property_contexts'
PLAT_SERVICE_CONTEXTS   = 'plat_service_contexts'
PLAT_HWSERVICE_CONTEXTS = 'plat_hwservice_contexts'
VENDOR_PROPERTY_CONTEXTS  = 'vendor_property_contexts'
VENDOR_HWSERVICE_CONTEXTS = 'vendor_hwservice_contexts'


def  is_mls_policy(policy_path: Path) -> bool:
    try:
        r = subprocess.run(
            ['file', str(policy_path)],
            capture_output=True, text=True
        )
        return ' MLS ' in r.stdout
    except Exception:
        return False  


def  find_policies_in_rom(rom_root: Path) -> list[Path]:
    found = []
    for rel in ROM_POLICY_CANDIDATES:
        p = rom_root / rel
        if not p.exists():
            print(f"  [~] Binary policy not found (skipping): {p}")
            continue
        if not is_mls_policy(p):
            print(f"  [~] Skipping non-MLS binary (first-stage policy, CIL covers this): {p}")
            continue
        found.append(p)
    return found


def  main():
    parser = argparse.ArgumentParser(
        description='Inject SELinux policy rules from a .te file into Android ROM policy files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
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
    parser.add_argument('--policy', nargs='+', metavar='POLICY_FILE',
                        help='One or more binary sepolicy files to patch directly')
    parser.add_argument('--system-selinux', metavar='DIR',
                        help='Path to system/etc/selinux directory '
                             '(for CIL, seapp_contexts, file_contexts, sha256 update)')
    parser.add_argument('--vendor-selinux', metavar='DIR',
                        help='Path to vendor/etc/selinux directory '
                             '(for vendor sidecar sha256 update)')
    parser.add_argument('--rom-root', metavar='DIR',
                        help='Root of an unpacked ROM; auto-discovers all targets')
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
    if args.validate or args.validate_full:
        if not args.rom_root:
            parser.error("--validate requires --rom-root")
        if args.te or args.remove_te or args.seapp or args.remove_seapp                or args.file_contexts or args.property_contexts                or args.service_contexts or args.hwservice_contexts:
            parser.error("--validate is standalone — do not combine with "
                         "--te / --seapp / --*-contexts flags")
        rr = Path(args.rom_root)
        if not rr.exists() or not rr.is_dir():
            parser.error(f"--rom-root path does not exist or is not a "
                         f"directory: {rr}")
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
    if not has_input and not args.rom_root:
        parser.error("Provide at least one of: --te, --remove-te, --seapp, --file-contexts")
    rules: list[TeRule] = []
    if args.te:
        print(f"[*] Parsing add rules: {args.te}")
        rules = parse_te_file(args.te)
        print(f"[*] Parsed {len(rules)} add rule(s)")
    else:
        print("[~] No --te file provided — skipping rule injection")
    remove_rules: list[RemoveRule] = []
    if args.remove_te:
        print(f"[*] Parsing remove rules: {args.remove_te}")
        remove_rules = parse_remove_te_file(args.remove_te)
        print(f"[*] Parsed {len(remove_rules)} remove rule(s)")
    if not rules and not remove_rules:
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
    if args.dry_run:
        print("\n[*] Dry-run mode — nothing will be written.\n")
        if rules:
            print("--- Rules to ADD ---")
            for r in rules:
                if r.op in ('allow', 'auditallow', 'dontaudit'):
                    print(f"  {r.op} {r.src} {r.tgt}:{r.cls} {  {' '.join(r.perms)} } ;")
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
                    print(f"  remove_allow {r.src} {r.tgt}:{r.cls} {  {' '.join(r.perms)} } ;")
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
                dr_conflicts, _dr_attr_map, _dr_all_types =                    find_neverallow_conflicts(rules, dr_cils)
                if not dr_conflicts:
                    print("  [OK] No neverallow conflicts detected.")
                else:
                    print(f"  [!] {len(dr_conflicts)} conflict(s) would be detected:")
                    for i, c in enumerate(dr_conflicts, 1):
                        rule = c.rule
                        na = c.neverallow
                        print(f"\n  Conflict {i}:")
                        print(f"    Adding:    allow {rule.src} {rule.tgt}:"
                              f"{rule.cls} {  {' '.join(rule.perms)} } ;")
                        print(f"    Violates:  {na.raw_line.strip()}")
                        print(f"    Source:    {na.cil_path}:{na.line_no}")
                        print(f"    Matched:   perm(s) {  {' '.join(c.matched_perms)} } ")
                        print(f"    Proposed:  {build_rewrite(c)}")
                    print("\n  In a non-dry run you'd be prompted to accept these rewrites.")
        return
    rom_root = Path(args.rom_root) if args.rom_root else None
    policies: list[Path] = []
    if not args.skip_binary:
        if args.policy:
            policies = [Path(p) for p in args.policy]
        if rom_root:
            policies.extend(find_policies_in_rom(rom_root))
    sys_selinux: Optional[Path] = None
    if args.system_selinux:
        sys_selinux = Path(args.system_selinux)
    elif rom_root:
        candidate = rom_root / ROM_SYSTEM_SELINUX
        if candidate.is_dir():
            sys_selinux = candidate
        else:
            print(f"  [~] system selinux dir not found: {candidate}")
    system_ext_selinux: Optional[Path] = None
    if rom_root:
        candidate = rom_root / ROM_SYSTEM_EXT_SELINUX
        if candidate.is_dir():
            system_ext_selinux = candidate
        else:
            print(f"  [~] system_ext selinux dir not found (skipping): {candidate}")
    vendor_selinux: Optional[Path] = None
    if args.vendor_selinux:
        vendor_selinux = Path(args.vendor_selinux)
    elif rom_root:
        candidate = rom_root / ROM_VENDOR_SELINUX
        if candidate.is_dir():
            vendor_selinux = candidate
        else:
            print(f"  [~] vendor selinux dir not found: {candidate}")
    rollback: Optional[RollbackSession] = None  
    neverallow_rewrites_ok: Optional[bool] = None
    mlsconstrain_rewrites_ok: Optional[bool] = None
    if rules and not args.skip_neverallow_check:
        print("\n[*] Pre-flight neverallow conflict scan")
        cil_paths_to_scan: list = []
        if sys_selinux:
            cil_paths_to_scan.append(('plat', sys_selinux / 'plat_sepolicy.cil'))
        if not args.plat_cil_only:
            if vendor_selinux:
                cil_paths_to_scan.append(('vendor', vendor_selinux / 'vendor_sepolicy.cil'))
                ppv_path = vendor_selinux / 'plat_pub_versioned.cil'
                if ppv_path.exists():
                    cil_paths_to_scan.append(('plat_pub_versioned', ppv_path))
            if system_ext_selinux:
                cil_paths_to_scan.append(('system_ext',
                                          system_ext_selinux / 'system_ext_sepolicy.cil'))
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
        na_attr_map: dict = {}
        na_all_types: set = set()
        if cil_paths_to_scan:
            conflicts, na_attr_map, na_all_types =                find_neverallow_conflicts(rules, cil_paths_to_scan)
        if conflicts or binary_findings:
            proceed = prompt_neverallow_conflicts(conflicts, binary_findings)
            if not proceed:
                print("\n[!] User declined neverallow rewrites.")
                print("[!] No files have been modified yet; exiting cleanly.")
                sys.exit(2)
            rollback = RollbackSession()
            print(f"\n[*] Rollback snapshot dir: {rollback.session_dir}")
            print("[*] User accepted; snapshotting files before modification")
            for _, cil_p in cil_paths_to_scan:
                if cil_p and cil_p.exists():
                    rollback.snapshot(cil_p)
            for pol in policies or []:
                rollback.snapshot(pol)
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
            neverallow_rewrites_ok = None  
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
            mls_conflicts, mc_attr_map, mc_all_types =                find_mlsconstrain_conflicts(rules, mls_cil_paths)
        if mls_conflicts:
            if args.assume_yes:
                print("\n[*] --yes/--assume-yes — skipping mlsconstrain prompt.")
                mls_proceed = True
            else:
                mls_proceed = prompt_mlsconstrain_conflicts(mls_conflicts)
            if not mls_proceed:
                print("\n[!] User declined mlsconstrain rewrites.")
                if rollback is None:
                    print("[!] No files have been modified yet; exiting cleanly.")
                    sys.exit(2)
                else:
                    print("[!] Keeping neverallow rewrites already applied; "
                          "skipping MLS widening.")
                    mlsconstrain_rewrites_ok = None
            else:
                if rollback is None:
                    rollback = RollbackSession()
                    print(f"\n[*] Rollback snapshot dir: {rollback.session_dir}")
                for _, cil_p in mls_cil_paths:
                    if cil_p and cil_p.exists():
                        rollback.snapshot(cil_p)
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
            mlsconstrain_rewrites_ok = None  
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
    vendor_aug_ok: Optional[bool] = None
    if not args.skip_cil:
        if sys_selinux:
            cil_path = sys_selinux / 'plat_sepolicy.cil'
            auto_coredomain_rules: list = []
            if rules and not args.no_auto_coredomain:
                detected = detect_new_domains(rules)
                if detected:
                    print(f"\n[*] Detected new domain(s): {', '.join(sorted(detected))}")
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
            explicit_coredomain_rules: list = []
            if args.coredomain:
                for t in args.coredomain:
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
            all_cil_rules = rules + auto_coredomain_rules + explicit_coredomain_rules
            if args.vendor_attr_add and vendor_selinux:
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
            if all_cil_rules:
                cil_ok = patch_cil(cil_path, all_cil_rules)
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
    cil_changed = (bool(cil_ok) or bool(cil_remove_ok)
                   or bool(neverallow_rewrites_ok) or bool(vendor_aug_ok)
                   or bool(mlsconstrain_rewrites_ok))
    if not args.skip_sha256 and cil_changed:
        if sys_selinux:
            sha_ok = update_sha256(sys_selinux, vendor_selinux, system_ext_selinux)
        else:
            print("[~] No system selinux dir — skipping SHA-256 update")
    print("\n" + "=" * 60)
    print("[*] Summary")
    print("=" * 60)
    all_ok = True


    def  _status(result: Optional[bool], label: str):
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