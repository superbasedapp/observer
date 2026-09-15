#!/usr/bin/env bash
# Disposable Apache Kafka/KRaft fixture; only this package is tested. No cloud,
# existing Kafka, source formatting, git or global test/lint actions.
set -euo pipefail
KAFKA_WORKDIR=$(mktemp -d /tmp/sbo-kafkalog-test.XXXXXX)
KAFKA_CONTAINER="sbo-kafkalog-test-$$-$RANDOM"
KAFKA_CONTAINER_ID=""
read -r KAFKA_PORT KAFKA_CONTROLLER_PORT < <(python3 -c 'import socket; sockets=[socket.socket(),socket.socket()]; [s.bind(("127.0.0.1",0)) for s in sockets]; print(*(s.getsockname()[1] for s in sockets)); [s.close() for s in sockets]')
cleanup() {
    local status=$?
    if [ -n "$KAFKA_CONTAINER_ID" ]; then
        docker logs "$KAFKA_CONTAINER_ID" > "$KAFKA_WORKDIR/broker.log" 2>&1 || true
        docker rm -f "$KAFKA_CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    echo "Kafka fixture logs: $KAFKA_WORKDIR/broker.log"
    exit "$status"
}
trap cleanup EXIT
KAFKA_CONTAINER_ID=$(docker run -d --name "$KAFKA_CONTAINER" --network host \
    -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
    -e "KAFKA_LISTENERS=PLAINTEXT://127.0.0.1:$KAFKA_PORT,CONTROLLER://127.0.0.1:$KAFKA_CONTROLLER_PORT" \
    -e "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:$KAFKA_PORT" \
    -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
    -e "KAFKA_CONTROLLER_QUORUM_VOTERS=1@127.0.0.1:$KAFKA_CONTROLLER_PORT" \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_OFFSETS_TOPIC_NUM_PARTITIONS=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
    -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=false \
    -e KAFKA_MESSAGE_MAX_BYTES=34078720 -e KAFKA_REPLICA_FETCH_MAX_BYTES=34078720 \
    -e KAFKA_MIN_INSYNC_REPLICAS=1 -e KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false \
    -e KAFKA_HEAP_OPTS="-Xms256M -Xmx512M" apache/kafka:3.9.1)
for attempt in $(seq 1 60); do
    if docker logs "$KAFKA_CONTAINER_ID" 2>&1 | rg -q 'Kafka Server started'; then break; fi
    if [ "$attempt" -eq 60 ]; then echo "Kafka fixture startup timed out" >&2; exit 1; fi
    sleep 1
done
OBSERVER_KAFKA_TEST_BROKERS="127.0.0.1:$KAFKA_PORT" GOTOOLCHAIN=go1.25.13 GOCACHE=/tmp/go-build-cache \
    go test -vet=off ./internal/telemetrylog/kafkalog -count=1 -timeout 5m "$@"
