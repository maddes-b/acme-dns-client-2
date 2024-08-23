#!/usr/bin/env sh
# shellcheck disable=SC2034
### https://github.com/acmesh-official/acme.sh/wiki/DNS-API-Dev-Guide
dns_acmednsclient2_info='acme-dns-client-2 wrapper for acme.sh
BEFORE retrieving a certificate: register the domains with acme-dns-client-2.sh
When using with amce.sh, then do NOT define any domain alias.
Site: https://auth.acme-dns.io/ (or self-hosted acme-dns)
      https://github.com/joohoi/acme-dns
Docs: https://github.com/maddes-b/acme-dns-client-2
      https://github.com/acmesh-official/acme.sh/wiki/dnsapi
Issues: https://github.com/maddes-b/acme-dns-client-2
Authors: Matthias "Maddes" Bücher
'

########  Public functions #####################

### Usage: dns_acmednsclient2_add <domain> <token>
### Add token as txt record to the challenge domain
dns_acmednsclient2_add () {
    _info "Using acme-dns-client-2: add (do NOT define any alias)"
    _debug "domain ${1}"
    _debug "token ${2}"

    RC=0
    acme-dns-client-2.sh update --domain "${1}" --token "${2}" || { RC="${?}" ; _err 'Use acme-dns-client-2.sh to list/register/check domain' ; }
    return "${RC}"
}

### Usage: dns_acmednsclient2_rm <domain> <token>
### Remove txt record with token from challenge domain
dns_acmednsclient2_rm () {
    _info "Using acme-dns-client-2: remove"
    _debug "domain ${1}"
    _debug "token ${2}"

    RC=0
    _debug "No implementation as acme-dns keeps only the last 2 txt records (normal/wildcard)"
    #acme-dns-client-2.sh clean --domain "${1}" --token "${2}" || { RC="${?}" ; _err 'Use acme-dns-client-2.sh to list/register/check domain' ; }
    return "${RC}"
}

####################  Private functions below ##################################
