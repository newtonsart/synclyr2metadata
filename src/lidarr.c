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
 *   lidarr_trackfile_path   — single retagged file (TrackRetag)
 *   lidarr_artist_path      — root directory of the artist
 *   lidarr_album_title      — title of the imported album
 */

#include "lidarr.h"
#include "http_client.h"
#include "metadata.h"
#include "sync.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
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

/* Lidarr normally exports lower-case names; accept original casing too. */
static const char *event_env(const char *lower, const char *original)
{
    const char *v = getenv(lower);
    return v && *v ? v : getenv(original);
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
static int lidarr_sync_list(TrackMetaList *list, const char *label, const char *plain_log, const char *missing_log)
{
    if (!list || list->count == 0) {
        if (list) metadata_list_free(list);
        log_msg("No audio files found in '%s'", label);
        return 1;
    }

    log_msg("Syncing %d track(s) in '%s'", list->count, label);

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
    return r.errors ? 1 : 0;
}

/* Process only the paths supplied by the event, not adjacent files. */
static TrackMetaList *list_from_paths(const char *paths, int single)
{
    TrackMetaList *list = calloc(1, sizeof(*list));
    char *copy = strdup(paths);
    if (!list || !copy) { free(list); free(copy); return NULL; }
    char *save = NULL;
    char *path = single ? copy : strtok_r(copy, "|", &save);
    while (path) {
        struct stat st;
        TrackMeta *meta = NULL;
        if (*path && stat(path, &st) == 0 && S_ISREG(st.st_mode))
            meta = metadata_read(path);
        if (!meta) {
            log_msg("ERROR: cannot read event track: %s", path);
            metadata_list_free(list);
            free(copy);
            return NULL;
        }
        TrackMeta **items = realloc(list->items, (list->count + 1) * sizeof(*items));
        if (!items) {
            metadata_free(meta);
            metadata_list_free(list);
            free(copy);
            return NULL;
        }
        list->items = items;
        list->items[list->count++] = meta;
        path = single ? NULL : strtok_r(NULL, "|", &save);
    }
    free(copy);
    return list;
}

/* ── Public API ───────────────────────────────────────────────────────── */

int lidarr_detect(void)
{
    return event_env("lidarr_eventtype", "Lidarr_EventType") != NULL;
}

int lidarr_run(const char *self_path)
{
    const char *event = event_env("lidarr_eventtype", "Lidarr_EventType");
    if (!event) return 1;
    if (strcmp(event, "Test") == 0) { log_msg("Test OK"); return 0; }
    int retag = strcmp(event, "TrackRetag") == 0;
    if (!retag && strcmp(event, "AlbumDownload") != 0) {
        log_msg("Ignoring event: %s", event);
        return 0;
    }

    /* Serialize event processes so the HTTP request budget is not multiplied. */
    char *lockpath = log_path_suffix(self_path, ".lock");
    int lockfd = lockpath ? open(lockpath, O_CREAT | O_RDWR, 0660) : -1;
    free(lockpath);
    if (lockfd < 0) { perror("Lidarr event lock"); return 1; }
    int locked;
    do { locked = flock(lockfd, LOCK_EX); } while (locked < 0 && errno == EINTR);
    if (locked < 0) { perror("Lidarr event lock"); close(lockfd); return 1; }

    char *logpath = log_path_suffix(self_path, ".log");
    if (logpath) { log_open(logpath); free(logpath); }
    char *plain_log = log_path_suffix(self_path, "_plain.log");
    char *missing_log = log_path_suffix(self_path, "_missing.log");
    const char *paths = retag
        ? event_env("lidarr_trackfile_path", "Lidarr_TrackFile_Path")
        : event_env("lidarr_addedtrackpaths", "Lidarr_AddedTrackPaths");
    char *album_dir = NULL;
    int rc = 1;
    log_msg("Event: %s", event);

    if (http_init() != 0) {
        log_msg("ERROR: HTTP initialization failed");
        goto done;
    }
    if (paths && *paths) {
        rc = lidarr_sync_list(list_from_paths(paths, retag), event, plain_log, missing_log);
    } else if (!retag) {
        album_dir = album_dir_from_title(event_env("lidarr_artist_path", "Lidarr_Artist_Path"),
                                         event_env("lidarr_album_title", "Lidarr_Album_Title"));
        if (album_dir) rc = lidarr_sync_list(metadata_scan_dir(album_dir), album_dir, plain_log, missing_log);
        else log_msg("ERROR: missing imported paths and album directory");
    } else {
        log_msg("ERROR: missing lidarr_trackfile_path");
    }
    http_cleanup();
done:
    free(album_dir);
    free(plain_log);
    free(missing_log);
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
    close(lockfd);
    return rc;
}
