FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PARPAR_VERSION=0.4.5

WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends software-properties-common ca-certificates \
    && add-apt-repository -y multiverse \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        nodejs \
        npm \
        p7zip-full \
        python-is-python3 \
        python3 \
        rar \
    && npm install -g "@animetosho/parpar@${PARPAR_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY .github/workflows/advarchiver-integration.yml .github/workflows/advarchiver-integration.yml
COPY advArchiver advArchiver

RUN chmod +x advArchiver/scripts/run_ci_guardrails.sh

CMD ["bash", "advArchiver/scripts/run_ci_guardrails.sh"]
