/*
 * lrclib.h — Client for the LRCLIB API (https://lrclib.net)
 *
 * Provides functions to retrieve synchronized lyrics
 * from the LRCLIB database.
 */

#ifndef LRCLIB_H
#define LRCLIB_H

/* Per-track lookup state: distinguish temporary API failures from misses. */
void lrclib_lookup_reset(void);
int lrclib_lookup_failed(void);


/* ── Types ─────────────────────────────────────────────────────────────── */

typedef struct {
    char *artist_name;
    char *track_name;
    char *album_name;
    double duration;
    char *synced_lyrics;
    char *plain_lyrics;
    int   instrumental;
} LrclibTrack;

/* ── Public API ────────────────────────────────────────────────────────── */

/*
 * Get the best matching track for the given metadata.
 * `album` and `duration` may be NULL / 0 to omit them.
 *
 * Returns a heap-allocated LrclibTrack on success, NULL if not found
 * or on error. Caller must free with lrclib_track_free().
 */
LrclibTrack *lrclib_get(const char *artist, const char *track,
                         const char *album, double duration);

/*
 * Search LRCLIB and pick the best candidate when the exact endpoint is too
 * strict. `prefer_synced` gives synced lyrics extra weight over plain lyrics.
 */
LrclibTrack *lrclib_search_best(const char *artist, const char *track,
                                 const char *album, double duration,
                                 int prefer_synced);

/* ── Memory management ─────────────────────────────────────────────────── */

void lrclib_track_free(LrclibTrack *track);

#endif /* LRCLIB_H */
