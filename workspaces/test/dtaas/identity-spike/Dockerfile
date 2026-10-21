FROM python:3.12.9-slim

# git: spike S3 pushes with the backup token to test write_repository.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests==2.32.5 "pyjwt[crypto]==2.15.1"

WORKDIR /spike
COPY spike_common.py spike_s3_gitlab.py spike_s4_keycloak.py ./

ENTRYPOINT ["python"]
