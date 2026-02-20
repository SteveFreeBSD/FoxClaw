FROM python:3.12-slim

ARG FIREFOX_CHANNEL=esr

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    bzip2 \
    ca-certificates \
    curl \
    firefox-esr \
    tini \
  && rm -rf /var/lib/apt/lists/*

RUN if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
      curl -L "https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=linux64&lang=en-US" | tar -xj -C /opt ; \
      ln -sf /opt/firefox/firefox /usr/bin/firefox ; \
    elif [ "$FIREFOX_CHANNEL" = "nightly" ]; then \
      curl -L "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US" | tar -xj -C /opt ; \
      ln -sf /opt/firefox/firefox /usr/bin/firefox ; \
    fi

ENV MOZ_HEADLESS=1
WORKDIR /workspace

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "echo 'Use scripts/firefox_container_scan.sh inside this container.'"]
