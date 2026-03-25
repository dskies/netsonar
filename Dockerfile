FROM python:3.12-alpine

# Copy pre-downloaded packages (populated by prepare-offline.ps1, or empty for online build)
COPY packages/apk/    /tmp/apk/
COPY packages/wheels/ /tmp/wheels/

# Install Alpine packages: offline if .apk files are present, online otherwise
RUN if ls /tmp/apk/*.apk 2>/dev/null | grep -q .; then \
        echo ">>> Offline: installing packages from local .apk files" && \
        apk add --no-network --allow-untrusted \
            /tmp/apk/libgcc-*.apk \
            /tmp/apk/libstdc++-*.apk \
            /tmp/apk/lua5.4-libs-*.apk \
            /tmp/apk/lua5.4-[0-9]*.apk \
            /tmp/apk/libpcap-*.apk \
            /tmp/apk/libssh2-*.apk \
            /tmp/apk/pcre2-*.apk \
            /tmp/apk/openssl-*.apk \
            /tmp/apk/ca-certificates-*.apk \
            /tmp/apk/nmap-[0-9]*.apk \
            /tmp/apk/nmap-nselibs-*.apk \
            /tmp/apk/nmap-scripts-*.apk \
            /tmp/apk/net-snmp-libs-*.apk \
            /tmp/apk/net-snmp-agent-libs-*.apk \
            /tmp/apk/net-snmp-[0-9]*.apk \
            /tmp/apk/net-snmp-tools-*.apk \
            /tmp/apk/libcap2-*.apk \
            /tmp/apk/libevent-*.apk \
            /tmp/apk/libexpat-*.apk \
            /tmp/apk/libdaemon-*.apk \
            /tmp/apk/dbus-libs-*.apk \
            /tmp/apk/dbus-[0-9]*.apk \
            /tmp/apk/avahi-libs-*.apk \
            /tmp/apk/avahi-[0-9]*.apk \
            /tmp/apk/avahi-tools-*.apk; \
    else \
        echo ">>> Online: downloading packages from Alpine repos" && \
        apk add --no-cache nmap nmap-nselibs nmap-scripts net-snmp net-snmp-tools avahi avahi-tools dbus; \
    fi \
    && rm -rf /tmp/apk

# Install Python packages: offline if wheels are present, online otherwise
RUN if ls /tmp/wheels/*.whl 2>/dev/null | grep -q .; then \
        echo ">>> Offline: installing Python packages from local wheels" && \
        pip install --no-index --find-links /tmp/wheels/ \
            fastapi uvicorn sqlalchemy apscheduler apprise \
            python-multipart aiofiles; \
    else \
        echo ">>> Online: downloading Python packages from PyPI" && \
        pip install --no-cache-dir \
            fastapi uvicorn sqlalchemy apscheduler apprise \
            python-multipart aiofiles; \
    fi \
    && rm -rf /tmp/wheels

WORKDIR /app
COPY app/ ./

# Data dir for SQLite volume mount
RUN mkdir -p /data

EXPOSE ${PORT:-8080}

# Shell form so ${PORT} env var is expanded at runtime
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --log-level info
