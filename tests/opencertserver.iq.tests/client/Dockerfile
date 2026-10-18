# ---------------------------------------------------------------------------
# OpenCertServer IQ client image
#
# A minimal Ubuntu container that hosts the *standard Linux tooling* used to drive
# a running, hardened OpenCertServer over the network. This is the "client" in the
# black-box Installation-Qualification model: every scenario in this project that
# asserts on the server does so by running one of the tools installed here.
#
# The image is intentionally tool-only: it carries no test runner. The Reqnroll
# step definitions start it with TestContainers (see Support/IqAcmeEnvironment.cs)
# and run each tool inside it via docker exec.
# ---------------------------------------------------------------------------
FROM ubuntu:26.04 AS estclient-build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils build-essential autoconf automake libtool libssl-dev liburiparser-dev \
 && rm -rf /var/lib/apt/lists/*

# Build the source behind Ubuntu's libest-utils 3.2.0+ds-1.1. Keep its portability
# fixes, but not enforce-http-1-0.patch: that patch rejects valid HTTP/1.1 responses.
WORKDIR /build
COPY libest-compat.patch /build/libest-compat.patch
RUN curl -fsSL https://archive.ubuntu.com/ubuntu/pool/universe/libe/libest/libest_3.2.0+ds.orig.tar.xz -o source.tar.xz \
 && curl -fsSL https://archive.ubuntu.com/ubuntu/pool/universe/libe/libest/libest_3.2.0+ds-1.1.debian.tar.xz -o debian.tar.xz \
 && echo '46d1150ff6f1ace3ccd9a9ab962cfafd275b7c52edb0fd4e868280672aa7cf0d  source.tar.xz' | sha256sum -c - \
 && echo '42cc6a7a7fa5d426b5ffbc4925c344328ef9a6b113858f59eb30db578bf0cd1f  debian.tar.xz' | sha256sum -c - \
 && mkdir source \
 && tar -xJf source.tar.xz -C source --strip-components=1 \
 && tar -xJf debian.tar.xz -C source \
 && cd source \
 && for fix in $(grep -vE '^[[:space:]]*(#|$)|enforce-http-1-0.patch' debian/patches/series); do \
      patch -p1 < "debian/patches/$fix" || exit 1; \
    done \
 && patch -l -F0 -p1 < /build/libest-compat.patch \
 && autoreconf -fi \
 && ./configure --prefix=/opt/libest --with-ssl-dir=/usr --with-uriparser-dir=/usr --enable-client-only \
 && make -j2 \
 && make install \
 && install -D LICENSE /opt/libest/share/doc/libest/LICENSE

FROM ubuntu:26.04

# 1. Standard HTTP/TLS + JSON tooling, all available through apt on Debian/Ubuntu.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      wget \
      openssl \
      jq \
      python3 \
      python3-pip \
      gnupg \
      socat \
      libicu78 \
      libssl3t64 \
      liburiparser1 \
 && rm -rf /var/lib/apt/lists/*

# 2. The real Cisco estclient; openssl independently checks its output.
COPY --from=estclient-build /opt/libest /opt/libest
RUN echo /opt/libest/lib > /etc/ld.so.conf.d/libest.conf \
 && ldconfig \
 && ln -s /opt/libest/bin/estclient /usr/local/bin/estclient \
 && test -x /usr/local/bin/estclient

# 3. The canonical ACME client, installed via the official bootstrap script
#    (fetched over curl; it is a plain Bash script, not an apt package). `socat`
#    (above) backs `acme.sh --standalone`, which answers the http-01 challenge on :80.
#    The release is pinned and installed without cron: the harness drives every run.
ARG ACME_SH_VERSION=3.1.1
RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" \
      | tar -xz -C /tmp \
 && cd "/tmp/acme.sh-${ACME_SH_VERSION}" \
 && ./acme.sh --install --nocron --home /root/.acme.sh \
 && cd / && rm -rf "/tmp/acme.sh-${ACME_SH_VERSION}" \
 && ln -s /root/.acme.sh/acme.sh /usr/local/bin/acme.sh \
 && acme.sh --version >/dev/null

# 4. The project's own CLI. The image is built with the `opencert` binary already
#    present on the image; the IQ harness copies the freshly built Linux binary at
#    image-build time so the CLI runs as a native binary, not via `dotnet run`.
#    The ARG is overridable per-image (e.g. CI builds the binary for the same RID).
ARG OPENCERT_BINARY=/opt/opencertserver/opencert
COPY opencert ${OPENCERT_BINARY}
RUN chmod +x ${OPENCERT_BINARY} \
 && ln -s "${OPENCERT_BINARY}" /usr/local/bin/opencert \
 && /usr/local/bin/opencert --help >/dev/null

WORKDIR /workspace

# Default is a no-op smoke that the IQ runner overrides per scenario; documented
# entrypoints live in the compose file (the harness runs them via the exec form).
ENTRYPOINT ["/bin/bash"]
CMD ["--version"]
