FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Ho_Chi_Minh \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    FLASK_PORT=8080


# Base tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg software-properties-common \
        python3 python3-pip jq tzdata \
    && rm -rf /var/lib/apt/lists/*


# Suricata (OISF stable PPA -> Suricata 7.x)
RUN add-apt-repository -y ppa:oisf/suricata-stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends suricata \
    && rm -rf /var/lib/apt/lists/*


# Zeek (OpenSUSE OBS repo). If 'zeek' ever fails to resolve on your arch,
# swap the package name for 'zeek-lts'.
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
        > /etc/apt/sources.list.d/security-zeek.list \
    && curl -fsSL 'https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key' \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/security-zeek.gpg \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:${PATH}"


# Suricata rules (ET Open). Build-time pull; can be refreshed at runtime.
# '|| true' so a transient network hiccup doesn't break the image build.
RUN suricata-update update-sources \
    && suricata-update --no-test --no-reload || true

# The compose service runs with cap_drop: ALL, which strips CAP_DAC_OVERRIDE.
# Without it, even root is bound by file mode bits, and the packaged
# suricata.yaml (mode 640) becomes unreadable -> Suricata exits before writing
# eve.json. Make its config + rules world-readable so it runs capability-less.
RUN chmod -R a+rX /etc/suricata /var/lib/suricata


# Python app
WORKDIR /opt/app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY app/ ./app/
COPY zeek/ ./zeek/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]