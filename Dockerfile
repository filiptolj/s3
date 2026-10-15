FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# Run with credentials, e.g.:
#   docker run -p 9000:9000 -v s3data:/data \
#     -e S3_ACCESS_KEY=admin -e S3_SECRET_KEY='use-a-long-random-secret' s3
# or mount a credentials file and set S3_CREDENTIALS_FILE.
FROM debian:bookworm-slim
COPY --from=build /src/target/release/s3 /usr/local/bin/s3
ENV S3_DATA=/data S3_ADDRESS=0.0.0.0:9000
VOLUME /data
EXPOSE 9000
HEALTHCHECK CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/9000 && printf 'GET /_health HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q OK <&3"]
ENTRYPOINT ["/usr/local/bin/s3"]
