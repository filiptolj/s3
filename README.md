# s3

A fast, lightweight, single-node S3-compatible object storage server written in Rust.

- One small binary with a low memory footprint; no GC, no external services.
- Works with the AWS CLI, boto3 and other AWS SDKs, the MinIO SDK and `mc`, rclone, Terraform and other S3 clients (path-style, or virtual-host style with `--domain`).
- Built for data safety: checksums on every stored file, a background scrubber, durable writes by default, and on-disk format versioning.

## Quick start

```sh
cargo build --release
S3_ACCESS_KEY=admin S3_SECRET_KEY='use-a-long-random-secret' ./target/release/s3 --data /srv/s3
```

```sh
export AWS_ACCESS_KEY_ID=admin AWS_SECRET_ACCESS_KEY='use-a-long-random-secret' AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:9000 s3 mb s3://photos
aws --endpoint-url http://localhost:9000 s3 sync ./pics s3://photos/
```

The server refuses to start without credentials, or with well-known default secrets.

## Running in production

- **HTTPS:** terminate TLS in a reverse proxy (Caddy, nginx, HAProxy) in front of the server. Set the proxy's maximum request body size to at least 5 GiB and turn off request buffering, so uploads stream through.
- **Credentials:** use `--credentials-file`, with one `access_key:secret_key` per line. All keys belong to the same account, so you can **rotate keys without downtime**: add the new key, send `SIGHUP` to reload, move clients to it, remove the old key, and `SIGHUP` again.
- **Durability:** the default `full` mode fsyncs data and metadata before acknowledging a write.
- **Disk space:** writes are refused with `507 InsufficientStorage` before free space drops below `--min-free-mb` (default 1 GiB), so the metadata database always has room.
- **Monitoring:** set `--metrics-token` and scrape `GET /_metrics` with `Authorization: Bearer <token>` (Prometheus format). Alert on `s3_corruptions_detected_total > 0` and on `s3_disk_free_bytes`. Use `GET /_health` for liveness checks; it needs no authentication.
- **Audit:** `--access-log` writes one JSON line per request to stdout. Each line records the time, request ID, client address, access key, operation, status, bytes and duration.
- **Backups:** this is a single-node server with no replication, so back up the data directory. The safest way is a filesystem snapshot (LVM, ZFS, btrfs); alternatively, stop the server and copy the directory, or mirror the buckets with `rclone sync` / `aws s3 sync`.
- **systemd:** see [`deploy/s3.service`](deploy/s3.service). Docker: see [`Dockerfile`](Dockerfile).

## Options

Every option can also be set through an environment variable (`s3 --help` prints the full list):

| Flag | Env | Default | Description |
|---|---|---|---|
| `--access-key` / `--secret-key` | `S3_ACCESS_KEY` / `S3_SECRET_KEY` | – | Credential pair |
| `--credentials-file` | `S3_CREDENTIALS_FILE` | – | `access_key:secret_key` lines, reloaded on SIGHUP |
| `--address` | `S3_ADDRESS` | `0.0.0.0:9000` | Listen address |
| `--data` | `S3_DATA` | `./data` | Data directory |
| `--region` | `S3_REGION` | `us-east-1` | Region reported to clients |
| `--domain` | `S3_DOMAIN` | – | Enable `<bucket>.<domain>` virtual-host style requests |
| `--durability` | `S3_DURABILITY` | `full` | `full` / `meta` / `relaxed` (see below) |
| `--min-free-mb` | `S3_MIN_FREE_MB` | `1024` | Free-space reserve |
| `--max-connections` | `S3_MAX_CONNECTIONS` | `4096` | Concurrent connection limit |
| `--upload-expiry-hours` | `S3_UPLOAD_EXPIRY_HOURS` | `168` | Abort incomplete multipart uploads after this (0 = never) |
| `--scrub-interval-days` | `S3_SCRUB_INTERVAL_DAYS` | `30` | Re-verify all data checksums this often (0 = never) |
| `--scrub-rate-mb` | `S3_SCRUB_RATE_MB` | `64` | Background scrub read limit in MiB/s |
| `--metrics-token` | `S3_METRICS_TOKEN` | – | Enables `/_metrics` behind this bearer token |
| `--access-log` | `S3_ACCESS_LOG=1` | off | JSON access log on stdout |
| `--anonymous` | `S3_ANONYMOUS=1` | off | Give unauthenticated requests **full access** (testing only) |
| `--disable-sigv2` | `S3_DISABLE_SIGV2=1` | off | Reject legacy SigV2 signatures |
| `--fast-etag` | `S3_FAST_ETAG=1` | off | xxh3 ETags instead of MD5 (see below) |
| `--owner-id` / `--owner-name` | `S3_OWNER_ID` / `S3_OWNER_NAME` | built-in | Account identity shown in ACLs and listings |
| `--inline-threshold` | `S3_INLINE` | `65536` | Objects up to this size are stored in the metadata DB |
| `--threads` | `S3_THREADS` | #cpus | Worker threads |
| `--cache-mb` | `S3_CACHE_MB` | `64` | Metadata page cache |

### Durability modes

| Mode | Data files | Metadata | Trade-off |
|---|---|---|---|
| `full` (default) | fsynced before the write is acknowledged | fsynced (group commit) | Every acknowledged write survives a power loss |
| `meta` | page cache | fsynced (group commit) | Process crashes are safe; a power loss can lose recently written data |
| `relaxed` | page cache | flushed at least every second | Fastest; a power loss can lose roughly the last second of writes |

Group commit batches concurrent writes into one fsync, so `full` stays fast under concurrent load.

### `--fast-etag`

S3 ETags are the MD5 of the content, and MD5 is slow enough to cap the speed of a single upload stream. With `--fast-etag`, ETags are computed with xxh3 instead. Single-part objects get a `-1` suffix so tools such as rclone don't mistake the value for an MD5. Integrity checks still apply: `Content-MD5`, `x-amz-content-sha256` and flexible checksums are always verified. Leave this off if a client compares `ETag` with an MD5.

## Data safety

- **Checksums at rest:** every data file has a CRC32C, verified whenever an object is read in full. If a file is corrupted, the download is aborted instead of returning bad data, and `s3_corruptions_detected_total` increases.
- **Scrubbing:** a rate-limited background scrub re-reads every file periodically. To check a stopped data directory on demand, run `s3 scrub --data <dir>`. It names any damaged object and exits with code 1. Corrupted objects are reported, never deleted automatically.
- **Garbage collection:** a reference index tracks every data file, all updated atomically with the metadata. The janitor removes files left behind by crashes once they are more than an hour old, along with stale temporary files and expired multipart uploads.
- **Format versioning:** `format.json` records the on-disk format, and the server refuses to open data written in a format it doesn't understand.
- **Exclusive access:** a second process cannot open the same data directory.
- **Robustness:**
  - Parsers that handle untrusted input (signatures, aws-chunked streams, XML, form uploads, ranges) have randomized and model-based tests.
  - Uploads are limited to 5 GiB per PUT or part, matching S3.
  - Stalled request bodies time out after 60 s, and request headers must arrive within 30 s.

## Supported API

- **Buckets:** ListBuckets (with pagination), CreateBucket, DeleteBucket (discards incomplete uploads, like S3), HeadBucket, GetBucketLocation, GetBucketVersioning (always unversioned), ListObjects v1/v2, ListObjectVersions (every object is its own `null` version), ListMultipartUploads, DeleteObjects, Get/PutBucketAcl, Get/Put/DeleteBucketCors.
- **Objects:**
  - PutObject, including conditional writes with `If-Match` and `If-None-Match`.
  - GetObject and HeadObject: Range, `partNumber`, `response-*` overrides, conditional headers.
  - DeleteObject, and CopyObject (COPY or REPLACE metadata).
  - Get/PutObjectAcl, GetObjectAttributes, GetObjectTagging (always empty).
  - **POST Object:** browser form uploads with signed policies, using SigV2 or SigV4.
- **Multipart:** Create, UploadPart, UploadPartCopy, Complete (retrying a completed upload is safe), Abort, ListParts.
- **Checksums:** CRC32, CRC32C, CRC64NVME, SHA1 and SHA256 are verified on upload and stored. They are returned with `x-amz-checksum-mode: ENABLED`. Multipart uploads support both COMPOSITE and FULL_OBJECT checksums.
- **Authentication:**
  - SigV4 in headers and presigned URLs.
  - SigV2 in headers and presigned URLs; boto3 still presigns with SigV2 by default.
  - aws-chunked streaming uploads (signed chunks, or unsigned with trailers).
  - POST policies.
- **Access control:** a single account, which can have multiple keys. Canned ACLs (`private`, `public-read`, `public-read-write`, `authenticated-read`) control anonymous access: public objects can be read without credentials, and only public buckets can be listed or written anonymously.
- **CORS:** per-bucket rules, preflight `OPTIONS`, and CORS headers on every response, including errors.
- **Not implemented:** versioning, object lock, bucket policies/IAM and multiple accounts, lifecycle rules, replication, event notifications, server-side encryption, built-in TLS, clustering/erasure coding.

Compatibility is tested against [Ceph s3-tests](https://github.com/ceph/s3-tests), the standard S3 conformance suite. The remaining failures are in the feature groups listed as not implemented.

## Design

- **Metadata** lives in an embedded B-tree ([redb](https://github.com/cberner/redb)). A single writer thread uses *group commit*: concurrent writes are batched into one transaction and one fsync. Reads use MVCC snapshots and never wait for writers. Listing is a sorted range scan, and common prefixes are skipped with a B-tree seek instead of walking every key below them.
- **Small objects** (64 KiB or less by default) are stored inline in the metadata DB, so no file is created, renamed or deleted for them. Their bytes live in a separate table, so HEAD and LIST only touch compact metadata.
- **Large objects** are written to a fresh, immutable file. Receiving the next batch, hashing the current one and writing it to disk run concurrently over the same zero-copy buffers.
- **Downloads** open all files first, so a concurrent overwrite can't break a running download, then stream with one read always in flight ahead of the socket.
- **CompleteMultipartUpload and CopyObject are O(1):** multipart parts are never concatenated (an object is a list of segments), and because data files are immutable, a copy is just a hard link.

On-disk layout: `format.json`, `meta.redb` (metadata, inline data, file index), `objects/ab/cd/<id>` (data files), and `tmp/` (in-progress uploads).

## Testing

```sh
cargo test                                   # unit, fuzz and model-based tests (FUZZ_ITERS=200000 for longer runs)
S3_ACCESS_KEY=test S3_SECRET_KEY=test-secret-123 ./target/release/s3 --data /tmp/s3-test &
S3_ACCESS_KEY=test S3_SECRET_KEY=test-secret-123 python3 tests/compat.py   # boto3 end-to-end suite (pip install boto3 awscrt)
```

## Limitations

- **Single node, single disk.** There is no replication, so corrupted data can be detected but not repaired. Use RAID or reliable storage underneath, and keep backups.
- **Single account.** Multiple keys exist for rotation, not for separate tenants with isolated permissions.
