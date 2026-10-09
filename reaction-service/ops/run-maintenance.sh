#!/bin/sh
# Run inside the existing container; do not start another alert consumer.
set -eu
exec /usr/bin/docker exec reaction python /app/maintenance.py cleanup \
    --pending-retention-days 30 --audit-retention-days 90
