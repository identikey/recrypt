//! Minio test helper — manages a Minio container for S3 integration tests.
//! Only compiled with the `s3-tests` feature.

#![cfg(feature = "s3-tests")]

use anyhow::{Context, Result, bail};
use aws_sdk_s3::Client;
use recrypt_server::config::StorageConfig;
use std::process::Command;
use std::time::Duration;

const MINIO_ENDPOINT: &str = "http://localhost:9000";
const MINIO_ACCESS_KEY: &str = "minioadmin";
const MINIO_SECRET_KEY: &str = "minioadmin";
const CONTAINER_NAME: &str = "recrypt-minio-test";

/// RAII guard for a Minio container used during S3 integration tests.
///
/// Creates a unique test bucket on construction and removes the container
/// on drop (unless `KEEP_MINIO=1` is set).
pub struct MinioContext {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl MinioContext {
    /// Start (or reuse) a Minio container, wait for it to be healthy,
    /// and create a fresh test bucket.
    pub async fn start() -> Result<Self> {
        let bucket = format!("recrypt-test-{}", uuid::Uuid::new_v4().simple());

        let ctx = Self {
            endpoint: MINIO_ENDPOINT.to_string(),
            bucket: bucket.clone(),
            access_key: MINIO_ACCESS_KEY.to_string(),
            secret_key: MINIO_SECRET_KEY.to_string(),
        };

        // Check if Minio is already reachable; if not, start Docker container.
        if !ctx.is_reachable().await {
            ctx.start_container()?;
        }

        // Wait for Minio health endpoint to respond.
        ctx.wait_healthy(30).await?;

        // Create the per-test bucket.
        ctx.create_bucket(&bucket).await?;

        Ok(ctx)
    }

    /// Check if Minio is already running and reachable at the expected endpoint.
    async fn is_reachable(&self) -> bool {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_default();
        client
            .get(format!("{}/minio/health/live", self.endpoint))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Launch the Minio Docker container.
    fn start_container(&self) -> Result<()> {
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                CONTAINER_NAME,
                "-p",
                "9000:9000",
                "-e",
                &format!("MINIO_ROOT_USER={}", MINIO_ACCESS_KEY),
                "-e",
                &format!("MINIO_ROOT_PASSWORD={}", MINIO_SECRET_KEY),
                "minio/minio",
                "server",
                "/data",
            ])
            .output()
            .context("failed to run docker")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already in use" — container may already be running.
            if !stderr.contains("already in use") {
                bail!("docker run failed: {}", stderr);
            }
        }

        Ok(())
    }

    /// Poll the Minio health endpoint until it responds or `max_secs` elapses.
    async fn wait_healthy(&self, max_secs: u64) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let health_url = format!("{}/minio/health/live", self.endpoint);

        for _ in 0..(max_secs * 5) {
            if let Ok(resp) = client.get(&health_url).send().await {
                if resp.status().is_success() {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        bail!("Minio did not become healthy within {}s", max_secs)
    }

    /// Build an S3 client pointed at this Minio instance.
    fn s3_client(&self) -> Client {
        let creds = aws_sdk_s3::config::Credentials::new(
            &self.access_key,
            &self.secret_key,
            None,
            None,
            "test",
        );
        let config = aws_sdk_s3::Config::builder()
            .endpoint_url(&self.endpoint)
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true)
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .build();
        Client::from_conf(config)
    }

    /// Create a bucket using the AWS SDK S3 client.
    async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.s3_client()
            .create_bucket()
            .bucket(bucket)
            .send()
            .await
            .with_context(|| format!("failed to create S3 bucket '{bucket}'"))?;
        Ok(())
    }

    /// Return a `StorageConfig` pointing the server at this Minio instance and bucket.
    pub fn storage_config(&self) -> StorageConfig {
        StorageConfig {
            backend: "s3".into(),
            s3_bucket: Some(self.bucket.clone()),
            s3_endpoint: Some(self.endpoint.clone()),
            local_path: None,
        }
    }
}

impl Drop for MinioContext {
    fn drop(&mut self) {
        if std::env::var("KEEP_MINIO").as_deref() == Ok("1") {
            return;
        }
        // Best-effort cleanup; ignore errors.
        let _ = Command::new("docker")
            .args(["rm", "-f", CONTAINER_NAME])
            .output();
    }
}
