-- Ephemeral cache table for release provenance payloads.
-- GitHub Releases and OSV/GHSA feeds remain the sources of truth;
-- every row here is disposable and rebuildable from scratch.

CREATE TABLE IF NOT EXISTS ephemeral_cache (
  cache_key TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  etag TEXT,
  expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ephemeral_cache_expires
  ON ephemeral_cache (expires_at);
