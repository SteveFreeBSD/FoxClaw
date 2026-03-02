# Elastic Fleet Lab Runbook

This directory contains a reproducible, Docker Compose-based lab environment for testing FoxClaw's Elastic Common Schema (ECS) NDJSON output against a live Elastic Security stack (Elasticsearch, Kibana, and Fleet Server).

## Prerequisites

1.  **Docker & Docker Compose** must be installed.
2.  **Environment Variables**: Create a `.env` file in this directory (it is git-ignored) to securely provide credentials without leaking them into the repository:

    ```bash
    # docker/elastic-fleet-lab/.env
    ELASTIC_PASSWORD="YOUR_SECURE_PASSWORD"
    KIBANA_ENCRYPTION_KEY="SOME_RANDOM_LONG_STRING_AT_LEAST_32_CHARS"
    FLEET_SERVER_SERVICE_TOKEN="YOUR_FLEET_TOKEN" # Optional, can be generated later
    ```

## Starting the Lab

To start the Elasticsearch, Kibana, and Fleet Server containers:

```bash
docker compose up -d
```

### Checking Health

You can verify the services are running and accessible:

*   **Elasticsearch**:
    ```bash
    curl -u elastic:${ELASTIC_PASSWORD} http://127.0.0.1:9200
    ```
*   **Kibana Status**:
    ```bash
    curl -I -u elastic:${ELASTIC_PASSWORD} http://127.0.0.1:5601/api/status
    ```

## Fleet Configuration

1.  **Open the Fleet UI**: Navigate to `http://localhost:5601` in your browser, log in with `elastic` and your configured password, and go to **Management -> Fleet**.
2.  **Generate a Fleet Server Service Token** (if not provided in `.env`):
    ```bash
    curl -s -u elastic:${ELASTIC_PASSWORD} \
      -X POST http://127.0.0.1:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-token
    ```

## Enrolling an Elastic Agent

To ingest FoxClaw's NDJSON output, enroll a containerized Elastic Agent and bind-mount the log file.

1.  In Kibana Fleet, create an Agent Policy with a **Custom Logs** integration pointing to the path `/logs/foxclaw.ecs.ndjson`.
2.  Enable advanced JSON parsing in the integration:
    ```yaml
    json:
      keys_under_root: true
      overwrite_keys: true
      add_error_key: true
    ```
3.  Start an Elastic Agent container, binding your local FoxClaw log:
    ```bash
    docker run -d --name foxclaw-agent --net host \
      -v /var/log/foxclaw/foxclaw.ecs.ndjson:/logs/foxclaw.ecs.ndjson:ro \
      -e FLEET_ENROLL=1 \
      -e FLEET_URL=https://127.0.0.1:8220 \
      -e FLEET_ENROLLMENT_TOKEN=<YOUR_ENROLLMENT_TOKEN_FROM_KIBANA> \
      -e FLEET_INSECURE=true \
      --user root \
      docker.elastic.co/beats/elastic-agent:8.17.0
    ```

## Verifying Ingestion

Run the following queries against Elasticsearch to confirm ECS compliance and indexing:

**Check Data Streams**:
```bash
curl -s -u elastic:${ELASTIC_PASSWORD} "http://127.0.0.1:9200/_data_stream?pretty"
```

**Check Document Body & JSON parsing**:
```bash
curl -s -u elastic:${ELASTIC_PASSWORD} -H 'Content-Type: application/json' \
  http://127.0.0.1:9200/logs-*/_search \
  -d '{"size":1,"query":{"match":{"observer.name":"FoxClaw"}}}'
```

**Check Mapping Types**:
```bash
curl -s -u elastic:${ELASTIC_PASSWORD} "http://127.0.0.1:9200/logs-*/_mapping" | head -n 100
```

**Confirm Alert Detection Rules Match**:
```bash
curl -s -u elastic:${ELASTIC_PASSWORD} -H 'Content-Type: application/json' \
  http://127.0.0.1:9200/logs-foxclaw.scan-default/_count \
  -d '{"query":{"bool":{"must":[{"term":{"event.kind":"alert"}},{"term":{"event.action":"foxclaw.finding"}}]}}}'
```
