/*
 * metadata.h — Audio file metadata reader using TagLib
 *
 * Reads metadata (title, artist, album, track number, duration)
 * from audio files. Supports FLAC, MP3, OGG, M4A, and more.
 */

#ifndef METADATA_H
#define METADATA_H

/* ── Types ─────────────────────────────────────────────────────────────── */

typedef struct {
    char *title;
    char *artist;
    char *album;
    int   track_number;
    int   has_lyrics;     /* Existing nonempty embedded lyrics */
    int   duration;       /* Duration in seconds */
    char *filepath;
} TrackMeta;

typedef struct {
    TrackMeta **items;
    int         count;
} TrackMetaList;

/* ── Public API ────────────────────────────────────────────────────────── */

/*
 * Read metadata from a single audio file.
 * Returns a heap-allocated TrackMeta on success, NULL on failure.
 * Caller must free with metadata_free().
 */
TrackMeta *metadata_read(const char *filepath);

/*
 * Scan a directory for audio files and read metadata from each.
 * Returns a heap-allocated TrackMetaList sorted by track number.
 * Caller must free with metadata_list_free().
 */
TrackMetaList *metadata_scan_dir(const char *dirpath);

/*
 * Check and write lyrics in a single TagLib file open.
 * If force=0 and lyrics already exist, skips writing.
 *
 * Returns:  1 = lyrics written
 *           0 = skipped (already has lyrics, force=0)
 *          -1 = error (could not open/save file)
 */
int metadata_sync_lyrics(const char *filepath, const char *lyrics, int force);

/* ── Memory management ─────────────────────────────────────────────────── */

void metadata_free(TrackMeta *meta);
void metadata_list_free(TrackMetaList *list);

#endif /* METADATA_H */
