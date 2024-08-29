#!/bin/sh -eu

### Setup etc dir
ETCDIR="${PREFIX:-}/etc/acme-dns-client"
#
[ -d "${ETCDIR}" ] || install -v -d -m u=rwx-s,g=rx-s,o=-s -- "${ETCDIR}"
chmod -c -- u=rwx-s,g=rx-s,o=-s "${ETCDIR}"
chown -c -- root:root "${ETCDIR}"
#
ETCFILE="${ETCDIR}/config.json"
if [ ! -s "${ETCFILE}" ]; then
  if [ -s "${ETCDIR}/config.json5" ]; then
    ### rename configuration file of <= 0.8.0 to configuration file name of 0.9.0+
    mv -v "${ETCDIR}/config.json5" "${ETCFILE}"
  else
    printf -- '{\n}\n' > "${ETCFILE}"
  fi
fi
chmod -c -- u=rw-s,g=r-s,o=-s "${ETCFILE}"
chown -c -- root:root "${ETCFILE}"
#
ETCFILE="${ETCDIR}/domain_accounts.json"
[ -s "${ETCFILE}" ] || printf -- '{\n}\n' > "${ETCFILE}"
chmod -c -- u=rw-s,g=r-s,o=-s "${ETCFILE}"
chown -c -- root:root "${ETCFILE}"

### Setup bin dir
BINDIR="${PREFIX:-}/usr/local/bin"
#
[ -d "${BINDIR}" ] || install -v -d -- "${BINDIR}"
#
install -v -- acme-dns-client-2.sh "${BINDIR}/"
install -v -- acme-dns-client-2.py "${BINDIR}/"
install -v -m u=rw-s,go=r-s -- acmednsclient2.py "${BINDIR}/"
