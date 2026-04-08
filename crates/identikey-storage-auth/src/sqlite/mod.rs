//! SQLite persistence backends

mod ownership;
mod schema;

pub use ownership::SqliteOwnershipStore;
pub use schema::{SCHEMA_VERSION, init_schema};
