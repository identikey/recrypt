# Recrypt Deployment Guide

**Status:** Phase 8 (documentation baseline)

This guide covers the operational setup and configuration of a Recrypt deployment.

---

## S3 Bucket Setup

### S3 Lifecycle Rule for Incomplete Multipart Uploads

Incomplete multipart uploads can accumulate if clients crash mid-upload. S3 provides
a lifecycle rule to automatically abort these after a grace period (default: 24 hours).

**Why this matters:** Without this rule, a failed client can leave stale part upload
state in S3, wasting storage quota and confusing garbage-collection logic.

#### Configuration via AWS CLI

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket recrypt-storage \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "abort-incomplete-multipart",
        "Status": "Enabled",
        "Filter": {
          "Prefix": "chunks/b3/"
        },
        "AbortIncompleteMultipartUpload": {
          "DaysAfterInitiation": 1
        }
      }
    ]
  }'
```

#### Configuration via XML (for S3 console or Terraform)

```xml
<LifecycleConfiguration>
  <Rule>
    <ID>abort-incomplete-multipart</ID>
    <Status>Enabled</Status>
    <Filter>
      <Prefix>chunks/b3/</Prefix>
    </Filter>
    <AbortIncompleteMultipartUpload>
      <DaysAfterInitiation>1</DaysAfterInitiation>
    </AbortIncompleteMultipartUpload>
  </Rule>
</LifecycleConfiguration>
```

**Customization:**

- `DaysAfterInitiation` — number of days before an incomplete upload is aborted.
  Default: 1 (24 hours). Can be reduced to 0 for more aggressive cleanup.
- `Prefix` — scopes the rule to the `chunks/b3/` prefix where encrypted file
  objects live. Does not affect metadata or other buckets.

### Orphan Garbage Collection

Two layers of orphan cleanup work together:

**Layer 1: Storage-level lifecycle rules** (covered above)
Automatically cleans up incomplete multipart uploads after the grace period.

**Layer 2: Application-level GC**

Run `recrypt-cli admin gc` periodically (e.g., daily cron job) to clean up
orphaned ciphertext and outboard objects:

```bash
# Dry run: report what would be deleted
recrypt-cli admin gc --dry-run

# Actually delete orphans
recrypt-cli admin gc
```

The command:
1. Scans all objects in the `chunks/b3/` prefix
2. Checks if each object has a metadata record in the auth service
3. Deletes orphaned ciphertext + outboard pairs (if no dry-run)

**Operational workflow:**

- Run dry-run first to verify the scan found the expected orphans
- Combine with periodic cron: e.g., `0 2 * * * recrypt-cli admin gc >> /var/log/recrypt-gc.log 2>&1`
- Monitor logs for unexpected orphan deletions

---

## Configuration

Server configuration lives in `recrypt-server.toml` or environment variables
prefixed with `RECRYPT_`. See [http-api-reference.md §5](http-api-reference.md#5-configuration-knobs-server-side)
for the full list of knobs.

**Common settings:**

```toml
host = "127.0.0.1"
port = 7222

[storage]
backend = "s3"
s3_bucket = "recrypt-storage"
s3_endpoint = "https://s3.amazonaws.com"
s3_region = "us-east-1"

[nonce]
window_secs = 300  # 5-minute replay window

pre_backend = "lattice"  # post-quantum default
```

---

## References

- [AWS S3 Lifecycle Configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html)
- [HTTP API Reference](http-api-reference.md)
- [Storage Design](storage-design.md)
