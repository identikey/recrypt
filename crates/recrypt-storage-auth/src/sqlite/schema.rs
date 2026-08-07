//! SQLite schema definitions

use crate::error::AuthResult;
use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 3;

/// Initialize the database schema.
///
/// Idempotent CREATE-IF-NOT-EXISTS plus version-gated ALTER migrations.
/// New columns or renames must come with a `migrate_*` step that brings
/// pre-existing v(n-1) databases forward.
pub fn init_schema(conn: &Connection) -> AuthResult<()> {
    let prior_version = current_version(conn)?;

    conn.execute_batch(
        r#"
        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );

        -- File ownership
        CREATE TABLE IF NOT EXISTS ownership (
            file_hash BLOB PRIMARY KEY,           -- 32 bytes Blake3
            owner_fingerprint BLOB NOT NULL,       -- 32 bytes
            created_at INTEGER NOT NULL            -- Unix timestamp
        );

        CREATE INDEX IF NOT EXISTS idx_ownership_owner
            ON ownership(owner_fingerprint);

        -- Access grants
        CREATE TABLE IF NOT EXISTS access_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash BLOB NOT NULL,
            owner_fingerprint BLOB NOT NULL,
            grantee_fingerprint BLOB NOT NULL,
            operations TEXT NOT NULL,              -- JSON array: ["read", "write"]
            expires_at INTEGER NOT NULL,           -- 0 = no expiry
            created_at INTEGER NOT NULL,
            UNIQUE(file_hash, grantee_fingerprint)
        );

        CREATE INDEX IF NOT EXISTS idx_grants_file
            ON access_grants(file_hash);
        CREATE INDEX IF NOT EXISTS idx_grants_grantee
            ON access_grants(grantee_fingerprint);

        -- Keyspaces (Phase B)
        CREATE TABLE IF NOT EXISTS keyspaces (
            id TEXT PRIMARY KEY,
            current_version INTEGER NOT NULL,
            current_hash TEXT NOT NULL,
            name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS keyspace_docs (
            hash TEXT PRIMARY KEY,
            keyspace_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            doc_bytes BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (keyspace_id) REFERENCES keyspaces(id)
        );
        CREATE INDEX IF NOT EXISTS idx_keyspace_docs_id_version
            ON keyspace_docs(keyspace_id, version);

        CREATE TABLE IF NOT EXISTS keyspace_members (
            keyspace_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            permissions TEXT NOT NULL,
            decryption_policy TEXT NOT NULL,
            PRIMARY KEY (keyspace_id, version, fingerprint)
        );
        CREATE INDEX IF NOT EXISTS idx_keyspace_members_fp
            ON keyspace_members(fingerprint);

        -- Grants (Phase B). Supersedes the legacy `access_grants` table, which
        -- is intentionally left in place: silent DROP on startup destroys any
        -- v1 data on disk. Operators on a v1 DB will see `access_grants` unused
        -- until an explicit migration path lands.
        CREATE TABLE IF NOT EXISTS grants (
            grant_id TEXT PRIMARY KEY,
            keyspace_id TEXT NOT NULL,
            keyspace_version INTEGER NOT NULL,
            subject TEXT NOT NULL,
            issuer TEXT NOT NULL,
            permissions TEXT NOT NULL,
            expires_at INTEGER,
            delegation_depth INTEGER NOT NULL,
            parent_grant TEXT,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            doc_bytes BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_grants_subject ON grants(subject);
        CREATE INDEX IF NOT EXISTS idx_grants_keyspace ON grants(keyspace_id);

    "#,
    )?;

    // v2 → v3: rename `capabilities` columns to `permissions` (recrypt-r1l).
    // Skipped on a fresh DB because CREATE TABLE above already names the
    // column `permissions`.
    if prior_version >= 2 && prior_version < 3 {
        migrate_v2_to_v3(conn)?;
    }

    // Set schema version. The PRIMARY KEY on `version` means INSERT OR
    // REPLACE adds rows when the version changes (the legacy code had this
    // bug); replace the table contents instead.
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?)",
        [SCHEMA_VERSION],
    )?;

    Ok(())
}

fn current_version(conn: &Connection) -> AuthResult<u32> {
    let version: u32 = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    Ok(version)
}

fn migrate_v2_to_v3(conn: &Connection) -> AuthResult<()> {
    // SQLite RENAME COLUMN requires 3.25+, which rusqlite bundles. The
    // version gate above means this only runs once per DB.
    conn.execute_batch(
        r#"
        ALTER TABLE keyspace_members RENAME COLUMN capabilities TO permissions;
        ALTER TABLE grants RENAME COLUMN capabilities TO permissions;
        "#,
    )?;
    Ok(())
}

/// Check schema version
#[allow(dead_code)]
pub fn check_version(conn: &Connection) -> AuthResult<u32> {
    current_version(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let version = check_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_v2_to_v3_migration_renames_columns() {
        // Simulate a v2 database with `capabilities` columns.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version VALUES (2);
            CREATE TABLE keyspace_members (
                keyspace_id TEXT, version INTEGER, fingerprint TEXT,
                capabilities TEXT, decryption_policy TEXT,
                PRIMARY KEY (keyspace_id, version, fingerprint)
            );
            CREATE TABLE grants (
                grant_id TEXT PRIMARY KEY, keyspace_id TEXT,
                keyspace_version INTEGER, subject TEXT, issuer TEXT,
                capabilities TEXT, expires_at INTEGER,
                delegation_depth INTEGER, parent_grant TEXT,
                created_at INTEGER, revoked INTEGER, doc_bytes BLOB
            );
            "#,
        )
        .unwrap();

        init_schema(&conn).unwrap();

        // Renamed columns are queryable; old name is not.
        conn.execute("INSERT INTO grants (grant_id, keyspace_id, keyspace_version, subject, issuer, permissions, delegation_depth, created_at, revoked, doc_bytes) VALUES ('g1', 'k1', 0, 's', 'i', 'read', 0, 0, 0, x'')", []).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM grants WHERE permissions = 'read'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);

        let version = check_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
