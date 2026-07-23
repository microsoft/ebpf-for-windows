# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

FROM ubuntu:22.04

SHELL ["/bin/bash", "-lc"]

ARG DEBIAN_FRONTEND=noninteractive
ARG TLAPS_VERSION=1.5.0
ARG TLAPS_RELEASE_TAG=202210041448
ARG TLAPS_INSTALLER=tlaps-1.5.0-x86_64-linux-gnu-inst.bin

# Minimal deps needed to download and run the TLAPS installer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      bash \
     make \
 && rm -rf /var/lib/apt/lists/*

# Install TLAPS under /opt/tlaps.
RUN set -euo pipefail \
 && curl -fsSL -o /tmp/${TLAPS_INSTALLER} "https://github.com/tlaplus/tlapm/releases/download/${TLAPS_RELEASE_TAG}/${TLAPS_INSTALLER}" \
 && chmod a+x /tmp/${TLAPS_INSTALLER} \
 && /tmp/${TLAPS_INSTALLER} -d /opt/tlaps \
 && rm -f /tmp/${TLAPS_INSTALLER}

ENV PATH="/opt/tlaps/bin:${PATH}"

# Default workdir matches how we'll mount the repo.
WORKDIR /repo

# Default command runs the proof runner.
CMD ["bash", "scripts/run_tlaps.sh"]
