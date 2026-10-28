FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["openssl"]
