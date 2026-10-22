FROM python:3.12.9-slim

RUN pip install --no-cache-dir requests==2.32.5 "pyjwt[crypto]==2.15.1"

WORKDIR /spike
COPY spike_common.py spike_s4_keycloak.py ./

ENTRYPOINT ["python", "spike_s4_keycloak.py"]
