# Logwatch Dashboard: one image for the board (web) and the worker (background jobs).
FROM python:3.13-slim

ARG UID=1000
ARG GID=1000
ARG WITH_TRIVY=0
# empty = latest release; pin e.g. v0.67.0
ARG TRIVY_VERSION=

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates curl tini iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && if [ "$WITH_TRIVY" = 1 ]; then \
      curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin $TRIVY_VERSION; \
    fi \
 && groupadd -o -g "$GID" lw && useradd -o -u "$UID" -g "$GID" -m -d /home/lw -s /usr/sbin/nologin lw

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY app/ /app/
COPY VERSION /app/VERSION
COPY installer/schema.py /app/featureschema.py
COPY remote/linux/logwatch-wafctl remote/linux/logwatch-nfwafctl /app/
WORKDIR /app
USER lw
ENV PYTHONUNBUFFERED=1 LOGWATCH_CONFIG=/config/config.yaml LOGWATCH_SECRETS=/secrets/secrets.env LOGWATCH_DATA=/data \
    LOGWATCH_SSH_KEY=/secrets/ssh/id_ed25519
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "web:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers", "--no-server-header"]
