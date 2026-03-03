#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

usage() {
    echo "Usage: $0 {up|status|down}"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

CMD=$1

if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-}"

wait_for_es() {
    echo "Waiting for Elasticsearch (http://127.0.0.1:9200)..."
    until curl -m 5 -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200/ -o /dev/null 2>/dev/null; do
        sleep 2
    done
}

wait_for_kibana() {
    echo "Waiting for Kibana (http://127.0.0.1:5601)..."
    until curl -m 5 -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:5601/api/status 2>/dev/null | grep -q 'available'; do
        sleep 2
    done
}

case "$CMD" in
    up)
        docker compose up -d
        wait_for_es
        wait_for_kibana
        echo ""
        echo "Services are reachable:"
        echo "- Elasticsearch: http://127.0.0.1:9200"
        echo "- Kibana: http://127.0.0.1:5601"
        ;;
    status)
        docker compose ps
        echo ""
        if curl -m 5 -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200/ -o /dev/null 2>/dev/null; then
            echo "Elasticsearch: OK (http://127.0.0.1:9200)"
        else
            echo "Elasticsearch: UNREACHABLE"
        fi
        
        if curl -m 5 -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:5601/api/status 2>/dev/null | grep -q 'available'; then
            echo "Kibana: OK (http://127.0.0.1:5601)"
        else
            echo "Kibana: UNAVAILABLE"
        fi
        ;;
    down)
        docker compose down
        ;;
    *)
        usage
        ;;
esac
