#!/bin/sh -eu
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil -*-

###
### acme-dns-client-2 for acme-dns servers - as combined Shell/Python script
### - the shell part creates and activates a fitting Python Virtual Environment
###   to not mess up the system's Python environment
### - the Python script implements the program logic
### - the client script can be used directly to register a domain, check the DNS
###   and acme-dns setup, and more. Execute with `[command] --help` for more details.
### - default configuration can be displayed via `config` command
### - the client script can be used as a manual authorization hook for dns-01
###   challenges via `certbot` command.
###
### License: GPLv2 - https://www.gnu.org/licenses/gpl-2.0.html
###
### Project page: https://github.com/maddes-b/acme-dns-client-2
###
### Authors:
### - Matthias "Maddes" Bücher <maddes@maddes.net>
###

PYTHON_VERSION='3' ; ### Use system default of python 3.x
SCRIPT_NAME="$(basename "${0}")"
SCRIPT_DIR="$(dirname "${0}")"
SCRIPT_PY_NAME="${SCRIPT_NAME%.sh}.py"
SCRIPT_PY_PATH="${SCRIPT_DIR}/${SCRIPT_PY_NAME}"

umask 0022

### Check for python module venv
RC=0 ; { "python${PYTHON_VERSION}" -m venv -h >/dev/null ; } || RC="${?}"
if [ "${RC}" -ne 0 ]; then
  printf -- '%s\n' 'Python support for Virtual Environments via "venv" missing. Please install via package manager.' 1>&2
  return "${RC}" 2>/dev/null || exit "${RC}"
fi

### Check for virtual environment for python version
VENV_PATH="${SCRIPT_DIR}/${SCRIPT_PY_NAME%.py}.venv-py${PYTHON_VERSION}"
CREATE=''
if [ ! -d "${VENV_PATH}" ]; then
  CREATE='X'
  printf -- '%s\n' "--- Initializing Python Virtual Environment at ${VENV_PATH}" 1>&2
  RC=0 ; "python${PYTHON_VERSION}" -m venv "${VENV_PATH}" || RC="${?}"
  if [ "${RC}" -ne 0 ]; then
    printf -- '%s\n' "Failed to set virtual environment up in ${VENV_PATH}." 1>&2
    return "${RC}" 2>/dev/null || exit "${RC}"
  fi
fi

### Activate virtual environment
set +u ; ### workaround for older venv versions
. "${VENV_PATH}/bin/activate"
set -u

unset -v PYTHON_VERSION RC SCRIPT_NAME SCRIPT_DIR SCRIPT_PY_NAME VENV_PATH

### Check for additional python packages in virtual environment
( ### sub-shell to protect original positional arguments
  DONT_CHECK='' ### SPEEDUP: disable with 'X' after virtual environment was created successfully the first time
  if [ -z "${DONT_CHECK}" -o -n "${CREATE}" ];  then
    PYTHON_MODULES='dnspython json5 requests'
    PYTHON_MODULES_VERSION='>=1.6 any >=2.0'
    set -- ${PYTHON_MODULES_VERSION}
    for PYTHON_MODULE in ${PYTHON_MODULES}
     do
      PYTHON_MODULE_VERSION="${1}"
      shift
      RC=0 ; { pip show -q "${PYTHON_MODULE}" 2>/dev/null ; } || RC="${?}"
      if [ "${RC}" -ne 0 ]; then
        CREATE='X'
        [ "${PYTHON_MODULE_VERSION}" != 'any' ] || PYTHON_MODULE_VERSION=''
        printf -- '%s\n' "--- Installing Python module ${PYTHON_MODULE}${PYTHON_MODULE_VERSION:+ ${PYTHON_MODULE_VERSION}}" 1>&2
        RC=0 ; { python -m pip install "${PYTHON_MODULE}${PYTHON_MODULE_VERSION}" 1>&2 ; } || RC="${?}"
        if [ "${RC}" -ne 0 ]; then
          printf -- '%s\n' 'Failed.' 1>&2
          return "${RC}" 2>/dev/null || exit "${RC}"
        fi
      fi
    done
    [ -z "${CREATE}" ] || printf -- '--- Initialization done\n\n' 1>&2
  fi
)

unset -v CREATE

ADC2_PATH="${0}" "${SCRIPT_PY_PATH}" "${@}"
