#!/bin/sh
set -eu

# A failed DNF transaction retains completed RPM downloads in its cache. Retry
# inside this one image layer so transient CDN disconnects make progress instead
# of discarding the cache and restarting the entire clean build from zero.
max_attempts=5
attempt=1

while ! dnf install -y \
    --setopt=install_weak_deps=False \
    --setopt=max_parallel_downloads=1 \
    --setopt=retries=20 \
    gcc cmake make perl; do
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "failed to install UBI build dependencies after $max_attempts attempts" >&2
        exit 1
    fi

    echo "UBI dependency download failed; retrying ($attempt/$max_attempts)" >&2
    sleep "$((attempt * 2))"
    attempt="$((attempt + 1))"
done

dnf clean all
