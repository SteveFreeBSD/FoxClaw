# Elastic Fleet Lab Runbook

This directory contains a reproducible, Docker Compose-based lab environment for testing FoxClaw's Elastic Common Schema (ECS) NDJSON output against a live Elastic Security stack (Elasticsearch, Kibana, and Fleet Server).

> Deprecated note: do not follow the older fixed-path Custom Logs flow with `/logs/foxclaw.ecs.ndjson`. The current supported ingest proof uses `scripts/siem_elastic_fleet_smoke.py`, which creates a temporary `filestream` package policy and rotates the ECS filename per run under `/var/log/foxclaw`.

## Prerequisites

1.  **Docker & Docker Compose** must be installed.
2.  **Environment Variables**: Create a `.env` file in this directory (it is git-ignored) to securely provide credentials without leaking them into the repository:

    ```bash
    # docker/elastic-fleet-lab/.env
    ELASTIC_PASSWORD="YOUR_SECURE_PASSWORD" # pragma: allowlist secret
    KIBANA_SYSTEM_PASSWORD="ANOTHER_SECURE_PASSWORD" # pragma: allowlist secret
    KIBANA_ENCRYPTION_KEY="SOME_RANDOM_LONG_STRING_AT_LEAST_32_CHARS"
    FLEET_SERVER_SERVICE_TOKEN="YOUR_FLEET_TOKEN" # Optional, can be generated later
    ```

## Starting the Lab

To start the Elasticsearch, Kibana, and Fleet Server containers:

```bash
./run_elastic_lab.sh up
```

### Checking Health

You can verify the services are running and accessible:

```bash
./run_elastic_lab.sh status
```

## Fleet Configuration

This lab uses HTTP inside the Docker network with basic auth; if TLS is enabled for Elasticsearch, ELASTICSEARCH_HOSTS and trust settings must be updated.

1.  **Open the Fleet UI**: Navigate to `http://localhost:5601` in your browser.
    - Log into Kibana UI with `elastic` / `ELASTIC_PASSWORD`.
    - Kibana uses `kibana_system` / `KIBANA_SYSTEM_PASSWORD` internally to talk to Elasticsearch.
    Then go to **Management -> Fleet**.
2.  **Generate a Fleet Server Service Token** (if not provided in `.env`):
    ```bash
    curl -s -u elastic:${ELASTIC_PASSWORD} \
      -X POST http://127.0.0.1:9200/_security/service/elastic/fleet-server/credential/token/fleet-server-token
    ```

## Managed-Ingest Proof

Use the repo-managed Fleet smoke runner instead of configuring a fixed log path by hand.

1.  Enroll the existing `foxclaw-agent` container into the `FoxClaw Agent Policy` once for this lab.
2.  From the repository root, run:
    ```bash
    .venv/bin/python scripts/siem_elastic_fleet_smoke.py \
      --output-dir /var/tmp/foxclaw-elastic-fleet-smoke \
      --profile tests/fixtures/firefox_profile \
      --ruleset foxclaw/rulesets/balanced.yml \
      --timeout-seconds 180
    ```
3.  The runner creates a temporary Fleet `filestream` package policy, writes a rotated ECS filename under `/var/log/foxclaw`, proves ingest, and then cleans up the temporary policy resources.

## Verifying Ingestion

Read `run_id`, `target_agent_id`, and `expected_index_name` from `/var/tmp/foxclaw-elastic-fleet-smoke/manifest.json`, then run the following query against Elasticsearch to confirm the current run and target agent were indexed:

```bash
curl -s -u elastic:${ELASTIC_PASSWORD} -H 'Content-Type: application/json' \
  http://127.0.0.1:9200/logs-foxclaw.scan-default/_count \
  -d '{"query":{"bool":{"filter":[{"term":{"data_stream.dataset":"foxclaw.scan"}},{"term":{"labels.foxclaw_run_id":"<run_id>"}},{"term":{"elastic_agent.id":"<target_agent_id>"}}]}}}'
```
