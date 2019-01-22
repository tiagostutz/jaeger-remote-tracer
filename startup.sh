#!/bin/bash
set -e
set -x

echo "Starting Jaeger Remote Tracer..."
echo $LISTEN_ADDRESS
echo $LISTEN_PORT
echo $JAEGER_SERVICE_NAME
echo $JAEGER_AGENT_HOST_PORT

jaeger-remote \
    --listen-address=$LISTEN_ADDRESS \
    --listen-port=$LISTEN_PORT \
    --jaeger-service-name=$JAEGER_SERVICE_NAME \
    --jaeger-agent-host-port=$JAEGER_AGENT_HOST_PORT