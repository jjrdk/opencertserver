#!/usr/bin/env sh
# certbot --manual dns-01 hook for the IQ harness: publishes (auth) or removes (cleanup) the
# _acme-challenge TXT record on the private authoritative test DNS server via its control API.
#   certbot certonly --manual --preferred-challenges dns \
#     --manual-auth-hook 'certbot-dns-iq.sh auth' --manual-cleanup-hook 'certbot-dns-iq.sh cleanup' -d <domain>
# certbot supplies CERTBOT_DOMAIN and CERTBOT_VALIDATION; IQ_DNS_API defaults to http://dns:8080.
set -eu
api="${IQ_DNS_API:-http://dns:8080}"
name="_acme-challenge.${CERTBOT_DOMAIN}"
case "${1:-}" in
  auth)
    curl -fsS -X POST "$api/records" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$name\",\"type\":\"TXT\",\"value\":\"$CERTBOT_VALIDATION\"}" >/dev/null ;;
  cleanup)
    curl -fsS -X DELETE "$api/records?name=$name&type=TXT&value=$CERTBOT_VALIDATION" >/dev/null ;;
  *)
    echo "usage: $0 auth|cleanup" >&2; exit 2 ;;
esac
