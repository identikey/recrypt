//! SQLite schema definitions

use crate::error::AuthResult;
use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 1;

/// Initialize the database schema
pub fn init_schema(conn: &Connection) -> AuthResult<()> {
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

    "#,
    )?;

    // Set schema version
    conn.execute(
        "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
        [SCHEMA_VERSION],
    )?;

    Ok(())
}

/// Check schema version
#[allow(dead_code)]
pub fn check_version(conn: &Connection) -> AuthResult<u32> {
    let version: u32 = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    Ok(version)
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
}
