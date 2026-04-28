//! OpenAPI document aggregator (epic recrypt-nj1).
//!
//! `ApiDoc` is the single source of truth for the recrypt HTTP API
//! schema. utoipa builds an OpenAPI 3.x document from `#[utoipa::path]`
//! annotations on handlers and `#[derive(ToSchema)]` types; this
//! aggregator just lists them.
//!
//! Endpoints are migrated incrementally — see recrypt-gpc (pilot) and
//! later child issues. Until at least one endpoint is annotated, this
//! document is intentionally empty and serves only to prove the
//! plumbing works end-to-end (server → /openapi.json → client codegen).
//!
//! Regenerate the on-disk snapshot consumed by `recrypt-client` with:
//! `just openapi-regen`.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "recrypt",
        description = "Recrypt proxy HTTP API. Endpoints are migrated to schema-as-source-of-truth incrementally (epic recrypt-nj1).",
        version = "0.1.0",
        license(name = "MIT OR Apache-2.0"),
    ),
    paths(),
    components(schemas()),
)]
pub struct ApiDoc;
