#!/usr/bin/env bash
# Minimal RFC 8555 client built only from curl, openssl and jq, for the IQ scenarios that need to
# observe raw protocol responses (status, headers, problem documents) or send payloads acme.sh
# never sends (e.g. "termsOfServiceAgreed" on an account update, or a JWS without a nonce).
#
#   acme-raw.sh <state-dir> <command> [args]
#     new-account                  create an account (RS256 key in <state-dir>/account.key) agreeing to the TOS
#     agree-tos                    POST {"termsOfServiceAgreed":true} to the account URL
#     new-order <domain>           POST a newOrder for a dns identifier
#     post-as-get <url>            authenticated resource read with an empty payload
#     answer <url> <json-file>     send challenge evidence with a fresh ACME JWS nonce
#     post-without-nonce <field>   POST a JWS whose protected header has no "nonce" to directory[field]
#
# ACME_DIRECTORY must name the directory URL. Every command prints the HTTP status code and leaves
# the response in <state-dir>/last.headers and <state-dir>/last.body.
set -euo pipefail

dir="$1"; cmd="$2"; shift 2
mkdir -p "$dir"
key="$dir/account.key"
: "${ACME_DIRECTORY:?ACME_DIRECTORY must be set}"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
hex2bin() { local hex; hex=$(cat); printf '%b' "$(printf '%s' "$hex" | sed 's/../\\x&/g')"; }

[ -f "$key" ] || openssl genrsa -out "$key" 2048 2>/dev/null

directory=$(curl -fsS "$ACME_DIRECTORY")
url_of() { printf '%s' "$directory" | jq -r --arg f "$1" '.[$f]'; }

jwk() {
  local n e
  n=$(openssl rsa -in "$key" -noout -modulus 2>/dev/null | cut -d= -f2 | hex2bin | b64url)
  e=$(printf '%06x' 65537 | hex2bin | b64url)
  printf '{"e":"%s","kty":"RSA","n":"%s"}' "$e" "$n"
}

nonce() {
  curl -fsS -I "$(url_of newNonce)" | tr -d '\r' | awk -F': ' 'tolower($1)=="replay-nonce"{print $2}'
}

# post <url> <payload-json> <key-identification: jwk|kid> [omit-nonce]
post() {
  local url="$1" payload="$2" ident="$3" omit="${4:-}" header protected body sig
  if [ "$ident" = jwk ]; then ident="\"jwk\":$(jwk)"; else ident="\"kid\":\"$(cat "$dir/account.url")\""; fi
  if [ -n "$omit" ]; then
    header="{\"alg\":\"RS256\",$ident,\"url\":\"$url\"}"
  else
    header="{\"alg\":\"RS256\",$ident,\"nonce\":\"$(nonce)\",\"url\":\"$url\"}"
  fi
  protected=$(printf '%s' "$header" | b64url)
  body=$(printf '%s' "$payload" | b64url)
  sig=$(printf '%s.%s' "$protected" "$body" | openssl dgst -sha256 -sign "$key" | b64url)
  curl -sS -o "$dir/last.body" -D "$dir/last.headers" -w '%{http_code}' \
    -H 'Content-Type: application/jose+json' \
    --data-binary "{\"protected\":\"$protected\",\"payload\":\"$body\",\"signature\":\"$sig\"}" "$url"
}

case "$cmd" in
  new-account)
    status=$(post "$(url_of newAccount)" '{"termsOfServiceAgreed":true}' jwk)
    tr -d '\r' < "$dir/last.headers" | awk -F': ' 'tolower($1)=="location"{print $2}' > "$dir/account.url"
    echo "$status" ;;
  agree-tos)
    post "$(cat "$dir/account.url")" '{"termsOfServiceAgreed":true}' kid; echo ;;
  new-order)
    post "$(url_of newOrder)" "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$1\"}]}" kid; echo ;;
  post-as-get)
    post "$1" '' kid; echo ;;
  answer)
    post "$1" "$(cat "$2")" kid; echo ;;
  post-without-nonce)
    post "$(url_of "$1")" '{"termsOfServiceAgreed":true}' jwk omit; echo ;;
  *)
    echo "unknown command: $cmd" >&2; exit 2 ;;
esac
