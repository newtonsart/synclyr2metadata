/*
 * sync.c — Shared lyrics sync engine
 *
 * Core pipeline: LRCLIB lookup → lyrics selection → metadata write.
 * Runs in parallel using worker threads with a shared work queue.
 */

#include "sync.h"
#include "http_client.h"
#include "lrclib.h"
#include "metadata.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* ── Internal context ─────────────────────────────────────────────────── */

typedef struct {
    const TrackMetaList *list;
    const SyncConfig    *config;
    int                  next_index;
    SyncResult           result;
    SyncProgressFn       progress;
    void                *user;
    FILE                *plain_file;
    FILE                *missing_file;
    pthread_mutex_t      mutex;
} SyncContext;

/* ── Track processing ─────────────────────────────────────────────────── */

static int try_local_lrc(const TrackMeta *t, const SyncConfig *cfg,
                         int *out_synced, int *out_skipped,
                         int *out_error, const char **out_status)
{
    char lrc_path[4096];
    snprintf(lrc_path, sizeof(lrc_path), "%s", t->filepath);
    char *dot = strrchr(lrc_path, '.');
    if (dot != NULL) {
        strcpy(dot, ".lrc");
    } else {
        strncat(lrc_path, ".lrc", sizeof(lrc_path) - strlen(lrc_path) - 1);
    }

    FILE *f_lrc = fopen(lrc_path, "rb");
    if (!f_lrc) return 0;

    fseek(f_lrc, 0, SEEK_END);
    long length = ftell(f_lrc);
    fseek(f_lrc, 0, SEEK_SET);

    if (length <= 0) {
        fclose(f_lrc);
        return 0;
    }

    char *buf = malloc((size_t)length + 1);
    if (!buf) {
        fclose(f_lrc);
        return 0;
    }

    size_t read_bytes = fread(buf, 1, (size_t)length, f_lrc);
    buf[read_bytes] = '\0';
    fclose(f_lrc);

    int rc = metadata_sync_lyrics(t->filepath, buf, cfg->force);
    free(buf);

    if (rc == 1) {
        *out_synced = 1;
        *out_status = "\xe2\x9c\x93 local lrc";
        if (cfg->clean_lrc) {
            unlink(lrc_path);
        }
    } else if (rc == 0) {
        *out_skipped = 1;
        *out_status = "\xe2\x8a\x98 already has lyrics";
    } else {
        *out_error = 1;
        *out_status = "\xe2\x9c\x97 write error";
    }
    return 1;
}

static int try_api_lrc(const TrackMeta *t, const SyncConfig *cfg,
                       int *out_synced, int *out_plain, int *out_skipped,
                       int *out_not_found, int *out_error, const char **out_status)
{
    lrclib_lookup_reset();
    /* Refined LRCLIB lookup: exact match first */
    LrclibTrack *lrc = lrclib_get(t->artist, t->title, t->album, (double)t->duration);

    if (!lrclib_lookup_failed() && cfg->prefer_synced &&
        (!lrc || (!lrc->instrumental &&
                  (!lrc->synced_lyrics || lrc->synced_lyrics[0] == '\0')))) {
        LrclibTrack *candidate = lrclib_search_best(t->artist, t->title, t->album,
                                                     (double)t->duration,
                                                     cfg->prefer_synced);
        if (candidate &&
            (candidate->instrumental ||
             (candidate->synced_lyrics && candidate->synced_lyrics[0] != '\0') ||
             !lrc || (!lrc->plain_lyrics || lrc->plain_lyrics[0] == '\0'))) {
            lrclib_track_free(lrc);
            lrc = candidate;
        } else {
            lrclib_track_free(candidate);
        }
    }

    /* Fallback: relax constraints if lyrics or track not found */
    if (!lrclib_lookup_failed() &&
        (!lrc || (!lrc->synced_lyrics && !lrc->plain_lyrics && !lrc->instrumental))) {
        lrclib_track_free(lrc);
        lrc = lrclib_get(t->artist, t->title, NULL, 0);
    }

    if (lrclib_lookup_failed()) {
        lrclib_track_free(lrc);
        *out_error = 1;
        *out_status = "API unavailable (retry later)";
        return 1;
    }

    if (!lrc) {
        *out_not_found = 1;
        *out_status = "\xe2\x9c\x97 not found";
        return 1;
    }

    /* Pick best available lyrics: synced first, then plain, then instrumental */
    const char *lyrics = NULL;
    int is_synced = 0;
    int is_inst = 0;

    if (lrc->instrumental) {
        *out_status = "\xe2\x9c\x93 instrumental";
        is_inst = 1;
    } else if (lrc->synced_lyrics && lrc->synced_lyrics[0] != '\0') {
        lyrics = lrc->synced_lyrics;
        *out_status = "\xe2\x9c\x93 synced";
        is_synced = 1;
    } else if (lrc->plain_lyrics && lrc->plain_lyrics[0] != '\0') {
        lyrics = lrc->plain_lyrics;
        *out_status = "\xe2\x9c\x93 plain";
    }

    if (!lyrics && !is_inst) {
        *out_not_found = 1;
        *out_status = "\xe2\x9c\x97 not found";
        lrclib_track_free(lrc);
        return 1;
    }

    if (is_inst) {
        /* User requested NOT to write [Instrumental] tags */
        *out_synced = 1; /* Count as success */
        lrclib_track_free(lrc);
        return 1;
    }

    /* Single TagLib open: check existing + write if needed */
    int rc = metadata_sync_lyrics(t->filepath, lyrics, cfg->force);
    lrclib_track_free(lrc);

    if (rc == 1) {
        if (is_synced) *out_synced = 1; else *out_plain = 1;
    } else if (rc == 0) {
        *out_skipped = 1;
        *out_status = "\xe2\x8a\x98 already has lyrics";
    } else {
        *out_error = 1;
        *out_status = "\xe2\x9c\x97 write error";
    }
    return 1;
}

static void process_track(const TrackMeta *t, const SyncConfig *cfg,
                          int *out_synced, int *out_plain,
                          int *out_skipped, int *out_not_found,
                          int *out_error, const char **out_status)
{
    *out_synced = *out_plain = *out_skipped = *out_not_found = *out_error = 0;

    if (!cfg->force && t->has_lyrics) {
        *out_skipped = 1;
        *out_status = "already has lyrics";
        return;
    }

    if (!t->artist || !t->title) {
        *out_not_found = 1;
        *out_status = "\xe2\x9c\x97 missing metadata";
        return;
    }

    if (try_local_lrc(t, cfg, out_synced, out_skipped, out_error, out_status)) {
        return;
    }

    try_api_lrc(t, cfg, out_synced, out_plain, out_skipped, out_not_found, out_error, out_status);
}

/* ── Worker thread ────────────────────────────────────────────────────── */

static void *sync_worker(void *arg)
{
    SyncContext *ctx = (SyncContext *)arg;

    for (;;) {
        pthread_mutex_lock(&ctx->mutex);
        int idx = ctx->next_index++;
        pthread_mutex_unlock(&ctx->mutex);

        if (idx >= ctx->list->count) break;

        const TrackMeta *t = ctx->list->items[idx];

        int s = 0, p = 0, sk = 0, nf = 0, e = 0;
        const char *status = "";
        process_track(t, ctx->config, &s, &p, &sk, &nf, &e, &status);

        pthread_mutex_lock(&ctx->mutex);

        ctx->result.synced    += s;
        ctx->result.plain     += p;
        ctx->result.skipped   += sk;
        ctx->result.not_found += nf;
        ctx->result.errors    += e;

        if (p && ctx->plain_file) {
            fprintf(ctx->plain_file, "%s\n", t->filepath);
            fflush(ctx->plain_file);
        }
        if (nf && ctx->missing_file) {
            fprintf(ctx->missing_file, "%s\n", t->filepath);
            fflush(ctx->missing_file);
        }

        if (ctx->progress) {
            ctx->progress(idx, ctx->list->count,
                          t->title ? t->title : "(unknown)",
                          status, ctx->user);
        }

        pthread_mutex_unlock(&ctx->mutex);
    }

    http_thread_cleanup();
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────── */

SyncResult sync_tracks(const TrackMetaList *list, const SyncConfig *config,
                         SyncProgressFn progress, void *user)
{
    SyncResult empty = {0};
    if (!list || list->count == 0 || !config) return empty;

    int t = config->num_threads > list->count ? list->count : config->num_threads;

    SyncContext ctx = {
        .list         = list,
        .config       = config,
        .next_index   = 0,
        .result       = {0},
        .progress     = progress,
        .user         = user,
        .plain_file   = config->out_plain ? fopen(config->out_plain, "a") : NULL,
        .missing_file = config->out_missing ? fopen(config->out_missing, "a") : NULL
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    pthread_t *threads = calloc((size_t)t, sizeof(pthread_t));
    for (int i = 0; i < t; i++) {
        pthread_create(&threads[i], NULL, sync_worker, &ctx);
    }
    for (int i = 0; i < t; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);

    if (ctx.plain_file) fclose(ctx.plain_file);
    if (ctx.missing_file) fclose(ctx.missing_file);

    return ctx.result;
}
