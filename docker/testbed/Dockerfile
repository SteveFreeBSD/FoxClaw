FROM python:3.12-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    firefox-esr \
    tini \
    xz-utils \
  && rm -rf /var/lib/apt/lists/*

ARG FIREFOX_CHANNEL=esr

RUN if [ "$FIREFOX_CHANNEL" = "beta" ] || [ "$FIREFOX_CHANNEL" = "nightly" ]; then \
      if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
        firefox_url="https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=linux64&lang=en-US"; \
      else \
        firefox_url="https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"; \
      fi; \
      curl --fail --show-error --silent --location "$firefox_url" -o /tmp/firefox.tar.xz; \
      tar -xJf /tmp/firefox.tar.xz -C /opt; \
      ln -sf /opt/firefox/firefox /usr/bin/firefox; \
      [ -x /usr/bin/firefox ]; \
      /usr/bin/firefox --version | tee /tmp/firefox-version.txt; \
      if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
        grep -q "b" /tmp/firefox-version.txt; \
      else \
        grep -q "a1" /tmp/firefox-version.txt; \
      fi; \
      rm -f /tmp/firefox.tar.xz /tmp/firefox-version.txt; \
    fi

ENV MOZ_HEADLESS=1
WORKDIR /workspace

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "echo 'Use scripts/firefox_container_scan.sh inside this container.'"]
