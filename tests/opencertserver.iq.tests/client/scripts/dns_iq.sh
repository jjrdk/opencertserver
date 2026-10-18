#!/usr/bin/env sh
# acme.sh DNS API hook for the IQ harness: publishes the dns-01 TXT record on the private
# authoritative test DNS server through its control API. IQ_DNS_API defaults to http://dns:8080.
#   acme.sh --issue --dns dns_iq --dnssleep 1 -d <domain> ...

dns_iq_add() {
  fulldomain="$1"
  txtvalue="$2"
  _info "Adding TXT $fulldomain via the IQ DNS control API"
  curl -fsS -X POST "${IQ_DNS_API:-http://dns:8080}/records" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$fulldomain\",\"type\":\"TXT\",\"value\":\"$txtvalue\"}" >/dev/null
}

dns_iq_rm() {
  fulldomain="$1"
  txtvalue="$2"
  _info "Removing TXT $fulldomain via the IQ DNS control API"
  curl -fsS -X DELETE "${IQ_DNS_API:-http://dns:8080}/records?name=$fulldomain&type=TXT&value=$txtvalue" >/dev/null
}
