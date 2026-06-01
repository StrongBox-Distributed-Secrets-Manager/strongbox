FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash openssl xxd socat ca-certificates python3 postgresql-client perl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN chmod +x /app/bin/strongbox /app/bin/strongbox-verify /app/lib/shamir.py /app/test/integration/run.sh
ENTRYPOINT ["/app/bin/strongbox"]
