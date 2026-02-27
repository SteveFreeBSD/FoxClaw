FROM python:3.12-slim

SHELL ["/bin/bash", "-e", "-u", "-o", "pipefail", "-c"]

COPY pyproject.toml README.md /tmp/foxclaw-build/

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    firefox-esr \
    tini \
    xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN python -c 'import pathlib, tomllib; \
data = tomllib.loads(pathlib.Path("/tmp/foxclaw-build/pyproject.toml").read_text(encoding="utf-8")); \
requirements = []; \
[requirements.append(item) for group in (data["build-system"]["requires"], data["project"]["dependencies"], data["project"]["optional-dependencies"]["dev"]) for item in group if item not in requirements]; \
print("\n".join(requirements))' >/tmp/foxclaw-build/requirements.txt

RUN python -m pip install --upgrade pip \
  && python -m pip install --no-cache-dir -r /tmp/foxclaw-build/requirements.txt \
  && rm -rf /tmp/foxclaw-build

ARG FIREFOX_CHANNEL=esr

RUN if [ "$FIREFOX_CHANNEL" = "beta" ] || [ "$FIREFOX_CHANNEL" = "nightly" ]; then \
      if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
        firefox_url="https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=linux64&lang=en-US"; \
      else \
        firefox_url="https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"; \
      fi; \
      cdn_root="https://download-installer.cdn.mozilla.net/pub/firefox"; \
      resolved_url="$(curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --output /dev/null --write-out '%{url_effective}' "$firefox_url")"; \
      case "$resolved_url" in \
        "$cdn_root"/*) ;; \
        *) echo "error: unexpected Firefox download host: $resolved_url" >&2; exit 1 ;; \
      esac; \
      curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 "$resolved_url" -o /tmp/firefox.tar.xz; \
      if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
        archive_rel_path="${resolved_url#"$cdn_root"/}"; \
        release_dir="$(printf '%s' "$archive_rel_path" | cut -d/ -f1-2)"; \
        checksum_target="${archive_rel_path#"$release_dir"/}"; \
        curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 "$cdn_root/$release_dir/SHA512SUMS" -o /tmp/firefox.SHA512SUMS; \
        expected_sha512="$(awk -v target="$checksum_target" '$2 == target {print $1; exit}' /tmp/firefox.SHA512SUMS)"; \
        [ -n "$expected_sha512" ]; \
        actual_sha512="$(sha512sum /tmp/firefox.tar.xz | awk '{print $1}')"; \
        [ "$actual_sha512" = "$expected_sha512" ]; \
      else \
        # latest-mozilla-central currently does not publish SHA512SUMS; validate hash from storage metadata header.
        expected_md5="$(curl --fail --show-error --silent --head --proto '=https' --tlsv1.2 "$resolved_url" | awk -F'md5=' '/^x-goog-hash: md5=/{gsub("\r", "", $2); print $2; exit}')"; \
        [ -n "$expected_md5" ]; \
        actual_md5="$(python3 -c "import base64, hashlib, pathlib; print(base64.b64encode(hashlib.md5(pathlib.Path('/tmp/firefox.tar.xz').read_bytes()).digest()).decode())")"; \
        [ "$actual_md5" = "$expected_md5" ]; \
      fi; \
      tar -xJf /tmp/firefox.tar.xz -C /opt; \
      ln -sf /opt/firefox/firefox /usr/bin/firefox; \
      [ -x /usr/bin/firefox ]; \
      /usr/bin/firefox --version | tee /tmp/firefox-version.txt; \
      if [ "$FIREFOX_CHANNEL" = "beta" ]; then \
        grep -q "b" /tmp/firefox-version.txt; \
      else \
        grep -q "a1" /tmp/firefox-version.txt; \
      fi; \
      rm -f /tmp/firefox.tar.xz /tmp/firefox.SHA512SUMS /tmp/firefox-version.txt; \
    fi

ENV MOZ_HEADLESS=1
WORKDIR /workspace

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "echo 'Use scripts/firefox_container_scan.sh inside this container.'"]
