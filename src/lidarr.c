/*
 * lidarr.c — Lidarr Custom Script integration
 *
 * Handles all Lidarr-specific logic: event detection, album directory
 * extraction, logging, and log rotation.  Replaces the old shell script
 * so only a single binary needs to be deployed.
 *
 * Lidarr environment variables used:
 *   lidarr_eventtype        — "Test", "AlbumDownload", "Grab", etc.
 *   lidarr_addedtrackpaths  — pipe-separated list of imported file paths
 *   lidarr_artist_path      — root directory of the artist
 *   lidarr_album_title      — title of the imported album
 */

#include "lidarr.h"
#include "http_client.h"
#include "metadata.h"
#include "sync.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define LIDARR_THREADS     4
#define MAX_LOG_SIZE       102400   /* 100 KB */
#define LOG_KEEP_LINES     200

/* ── Logging ──────────────────────────────────────────────────────────── */

static FILE *log_fp = NULL;

/*
 * Derive a log file path from the binary's own path plus a suffix.
 * e.g. "/config/scripts/synclyr2metadata" + ".log"
 */
static char *log_path_suffix(const char *self_path, const char *suffix)
{
    size_t len = strlen(self_path) + strlen(suffix) + 1;
    char *path = malloc(len);
    if (path) {
        snprintf(path, len, "%s%s", self_path, suffix);
    }
    return path;
}

/*
 * Rotate the log file if it exceeds MAX_LOG_SIZE.
 * Keeps the last LOG_KEEP_LINES lines.
 */
static void log_rotate(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= MAX_LOG_SIZE) {
        return;
    }

    FILE *f = fopen(path, "r");
    if (!f) return;

    /* Count total lines */
    int total = 0;
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (ch == '\n') total++;
    }

    if (total <= LOG_KEEP_LINES) {
        fclose(f);
        return;
    }

    /* Skip to the line we want to keep from */
    rewind(f);
    int skip = total - LOG_KEEP_LINES;
    for (int i = 0; i < skip; i++) {
        while ((ch = fgetc(f)) != EOF && ch != '\n') {}
    }

    /* Read the tail into memory */
    long pos = ftell(f);
    long tail_size = st.st_size - pos;
    char *buf = malloc((size_t)tail_size + 1);
    if (!buf) { fclose(f); return; }

    size_t n = fread(buf, 1, (size_t)tail_size, f);
    buf[n] = '\0';
    fclose(f);

    /* Overwrite the file with just the tail */
    f = fopen(path, "w");
    if (f) {
        fwrite(buf, 1, n, f);
        fclose(f);
    }
    free(buf);
}

/*
 * Open the log file for appending (after optional rotation).
 */
static int log_open(const char *path)
{
    log_rotate(path);
    log_fp = fopen(path, "a");
    return log_fp ? 0 : -1;
}

/*
 * Write a timestamped message to the log file and stdout.
 */
static void log_msg(const char *fmt, ...)
{
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    va_list ap;

    if (log_fp) {
        va_start(ap, fmt);
        fprintf(log_fp, "[%s] ", timestamp);
        vfprintf(log_fp, fmt, ap);
        fprintf(log_fp, "\n");
        fflush(log_fp);
        va_end(ap);
    }

    va_start(ap, fmt);
    printf("[%s] ", timestamp);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

/* ── Album directory detection ────────────────────────────────────────── */

/*
 * Extract the album directory from lidarr_addedtrackpaths.
 * The variable contains pipe-separated full file paths.
 * We take the first path and strip the filename to get the directory.
 *
 * Returns a heap-allocated string, or NULL if not available.
 */
static char *album_dir_from_tracks(void)
{
    const char *paths = getenv("lidarr_addedtrackpaths");
    if (!paths || !paths[0]) return NULL;

    /* Isolate the first path (before the first '|') */
    const char *sep = strchr(paths, '|');
    size_t len = sep ? (size_t)(sep - paths) : strlen(paths);

    char *first = malloc(len + 1);
    if (!first) return NULL;
    memcpy(first, paths, len);
    first[len] = '\0';

    /* Strip the filename → keep only the directory */
    char *slash = strrchr(first, '/');
    if (slash && slash != first) {
        *slash = '\0';
    }

    return first;
}

/*
 * Fallback: search for a subdirectory matching the album title
 * under the artist's path.
 *
 * Returns a heap-allocated string, or NULL if not found.
 */
static char *album_dir_from_title(const char *artist_path, const char *title)
{
    if (!artist_path || !title) return NULL;

    DIR *dir = opendir(artist_path);
    if (!dir) return NULL;

    char *result = NULL;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (strstr(entry->d_name, title)) {
            size_t len = strlen(artist_path) + strlen(entry->d_name) + 2;
            result = malloc(len);
            if (result) {
                snprintf(result, len, "%s/%s", artist_path, entry->d_name);
            }
            break;
        }
    }

    closedir(dir);
    return result;
}

/* ── Lidarr sync helpers ──────────────────────────────────────────────── */

/*
 * Progress callback: writes each track's status to the log.
 */
static void lidarr_progress(int idx, int total, const char *title,
                             const char *status, void *user)
{
    (void)user;
    log_msg("  [%2d/%d] %-40.40s %s", idx + 1, total, title, status);
}

/*
 * Scan and sync a single directory, logging results.
 */
static void lidarr_sync_dir(const char *dirpath, const char *plain_log, const char *missing_log)
{
    TrackMetaList *list = metadata_scan_dir(dirpath);
    if (!list || list->count == 0) {
        if (list) metadata_list_free(list);
        log_msg("No audio files found in '%s'", dirpath);
        return;
    }

    log_msg("Syncing %d track(s) in '%s'", list->count, dirpath);

    SyncConfig config = {
        .force         = 0,
        .clean_lrc     = 0,  /* Safe default for Lidarr */
        .prefer_synced = 1,
        .num_threads   = LIDARR_THREADS,
        .out_plain     = (char *)plain_log,
        .out_missing   = (char *)missing_log
    };

    SyncResult r = sync_tracks(list, &config, lidarr_progress, NULL);
    metadata_list_free(list);

    log_msg("Done: %d synced, %d plain, %d skipped, %d not found, %d errors",
            r.synced, r.plain, r.skipped, r.not_found, r.errors);
}

/* ── Public API ───────────────────────────────────────────────────────── */

int lidarr_detect(void)
{
    return getenv("lidarr_eventtype") != NULL;
}

int lidarr_run(const char *self_path)
{
    /* Set up logging next to the binary */
    char *logpath = log_path_suffix(self_path, ".log");
    if (logpath) {
        log_open(logpath);
        free(logpath);
    }

    char *plain_log = log_path_suffix(self_path, "_plain.log");
    char *missing_log = log_path_suffix(self_path, "_missing.log");

    /* Read event type */
    const char *event = getenv("lidarr_eventtype");
    if (!event) {
        log_msg("ERROR: lidarr_eventtype not set");
        return 1;
    }

    /* Handle events */
    if (strcmp(event, "Test") == 0) {
        log_msg("Test OK");
        return 0;
    }

    if (strcmp(event, "AlbumDownload") != 0) {
        log_msg("Ignoring event: %s", event);
        return 0;
    }

    /* AlbumDownload event — find the album directory */
    const char *artist_path = getenv("lidarr_artist_path");

    /* Strategy 1: derive from imported track paths */
    char *album_dir = album_dir_from_tracks();

    /* Strategy 2: match album title under artist directory */
    if ((!album_dir || album_dir[0] == '\0') && artist_path) {
        free(album_dir);
        album_dir = album_dir_from_title(artist_path,
                                          getenv("lidarr_album_title"));
    }

    /* Sync the album or fall back to the entire artist */
    http_init();

    if (album_dir && album_dir[0] != '\0') {
        log_msg("Album: %s", album_dir);
        lidarr_sync_dir(album_dir, plain_log, missing_log);
    } else if (artist_path) {
        log_msg("Album dir not found, syncing artist: %s", artist_path);
        /* Iterate artist subdirs */
        DIR *dir = opendir(artist_path);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                size_t len = strlen(artist_path) + strlen(entry->d_name) + 2;
                char *sub = malloc(len);
                if (!sub) continue;
                snprintf(sub, len, "%s/%s", artist_path, entry->d_name);

                struct stat st;
                if (stat(sub, &st) == 0 && S_ISDIR(st.st_mode)) {
                    lidarr_sync_dir(sub, plain_log, missing_log);
                }
                free(sub);
            }
            closedir(dir);
        }
    } else {
        log_msg("ERROR: could not determine album directory");
    }

    free(album_dir);
    free(plain_log);
    free(missing_log);
    http_cleanup();

    if (log_fp) fclose(log_fp);
    return 0;
}
