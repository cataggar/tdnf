#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${1:-${ROOT_DIR}/out}"
if [[ "${PREFIX}" != /* ]]; then
    PREFIX="${ROOT_DIR}/${PREFIX#./}"
fi

LIBEXEC="${PREFIX}/libexec/tdnf"
WORK_DIR="${PREFIX}/.rpmzig-smoke.$$"
TOP_DIR="${WORK_DIR}/rpmbuild"
DB_ROOT="${WORK_DIR}/root"
KEY_ROOT="${WORK_DIR}/key-root"
GNUPG_ROOT="${WORK_DIR}/gnupg"
RPM_TMP="${WORK_DIR}/rpm-tmp"

cleanup() {
    rm -rf -- "${WORK_DIR}"
}
if [[ -e "${WORK_DIR}" ]]; then
    echo "Refusing to reuse existing smoke directory: ${WORK_DIR}" >&2
    exit 1
fi
trap cleanup EXIT

mkdir -p \
    "${TOP_DIR}/BUILD" \
    "${TOP_DIR}/BUILDROOT" \
    "${TOP_DIR}/RPMS" \
    "${TOP_DIR}/SOURCES" \
    "${TOP_DIR}/SPECS" \
    "${TOP_DIR}/SRPMS" \
    "${DB_ROOT}" \
    "${KEY_ROOT}" \
    "${GNUPG_ROOT}" \
    "${RPM_TMP}"
chmod 0700 "${GNUPG_ROOT}"
export TMPDIR="${RPM_TMP}"

for binary in \
    tdnf-rpmdb-count \
    tdnf-rpmdb-list \
    tdnf-rpmdb-pubkeys \
    tdnf-rpmdb-import-pubkeys \
    tdnf-rpmdb-write \
    tdnf-rpm-info \
    tdnf-rpm-files \
    tdnf-rpm-verify \
    tdnf-rpm-install \
    tdnf-rpm-erase \
    tdnf-rpm-trigger \
    tdnf-rpm-scriptlet
do
    test -x "${LIBEXEC}/${binary}"
done

rpmbuild \
    --define "_topdir ${TOP_DIR}" \
    --define "_tmppath ${RPM_TMP}" \
    -bb "${ROOT_DIR}/scripts/fixtures/tdnf-rpmzig-smoke.spec"
rpmbuild \
    --define "_topdir ${TOP_DIR}" \
    --define "_tmppath ${RPM_TMP}" \
    -bb "${ROOT_DIR}/scripts/fixtures/tdnf-rpmzig-smoke-target.spec"

mapfile -d '' owner_matches < <(
    find "${TOP_DIR}/RPMS" -type f \
        -name 'tdnf-rpmzig-smoke-1.0.0-1.noarch.rpm' -print0
)
mapfile -d '' target_matches < <(
    find "${TOP_DIR}/RPMS" -type f \
        -name 'tdnf-rpmzig-smoke-target-1.0.0-1.noarch.rpm' -print0
)
if [[ "${#owner_matches[@]}" -ne 1 || "${#target_matches[@]}" -ne 1 ]]; then
    echo "Expected one owner and one target smoke RPM" >&2
    exit 1
fi
OWNER_RPM="${owner_matches[0]}"
TARGET_RPM="${target_matches[0]}"

export GNUPGHOME="${GNUPG_ROOT}"
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key \
    'tdnf rpmzig smoke <rpmzig-smoke@tdnf.invalid>' rsa2048 sign 0
KEY_FINGERPRINT="$(
    gpg --batch --with-colons --list-keys \
        'rpmzig-smoke@tdnf.invalid' |
        awk -F: '/^fpr:/ { print $10; exit }'
)"
test -n "${KEY_FINGERPRINT}"
PUBLIC_KEY="${WORK_DIR}/pubkey.asc"
gpg --batch --armor --export "${KEY_FINGERPRINT}" > "${PUBLIC_KEY}"
test -s "${PUBLIC_KEY}"

rpmsign \
    --define "_gpg_name ${KEY_FINGERPRINT}" \
    --define "__gpg /usr/bin/gpg" \
    --define "_tmppath ${RPM_TMP}" \
    --addsign "${OWNER_RPM}"

export LD_LIBRARY_PATH="${PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

INFO_OUTPUT="$("${LIBEXEC}/tdnf-rpm-info" "${OWNER_RPM}")"
grep -Fq 'NEVRA:       tdnf-rpmzig-smoke-1.0.0-1.noarch' \
    <<< "${INFO_OUTPUT}"
FILES_OUTPUT="$("${LIBEXEC}/tdnf-rpm-files" "${OWNER_RPM}")"
grep -Fq './var/lib/tdnf-rpmzig-smoke/payload' <<< "${FILES_OUTPUT}"

"${LIBEXEC}/tdnf-rpm-verify" \
    "${OWNER_RPM}" --key "${PUBLIC_KEY}" |
    grep -Fq 'Result:    OK'

IMPORTED="$(
    "${LIBEXEC}/tdnf-rpmdb-import-pubkeys" \
        "${KEY_ROOT}" "${PUBLIC_KEY}"
)"
[[ "${IMPORTED}" == "1" ]]
PUBKEY_OUTPUT="$(
    "${LIBEXEC}/tdnf-rpmdb-pubkeys" "${KEY_ROOT}"
)"
grep -Eiq '^[[:xdigit:]]+[[:space:]]+[1-9][0-9]*$' \
    <<< "${PUBKEY_OUTPUT}"
"${LIBEXEC}/tdnf-rpm-verify" \
    "${OWNER_RPM}" --rpmdb "${KEY_ROOT}" |
    grep -Fq 'Result:    OK'

run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        unshare -Ur "$@"
    fi
}

run_as_root "${LIBEXEC}/tdnf-rpm-install" \
    --root "${DB_ROOT}" "${OWNER_RPM}"
grep -Fxq 'payload' \
    "${DB_ROOT}/var/lib/tdnf-rpmzig-smoke/payload"

HNUM="$(
    "${LIBEXEC}/tdnf-rpmdb-write" \
        install "${DB_ROOT}" "${OWNER_RPM}" 1 1 3
)"
[[ "${HNUM}" =~ ^[1-9][0-9]*$ ]]
[[ "$("${LIBEXEC}/tdnf-rpmdb-count" "${DB_ROOT}")" == "1" ]]
LIST_OUTPUT="$("${LIBEXEC}/tdnf-rpmdb-list" "${DB_ROOT}")"
grep -Fxq 'tdnf-rpmzig-smoke-1.0.0-1.noarch' <<< "${LIST_OUTPUT}"

run_as_root "${LIBEXEC}/tdnf-rpm-scriptlet" \
    --root "${DB_ROOT}" \
    --phase pre \
    --arg1 1 \
    --rpmdefine "_tmppath /var/lib/tdnf-rpmzig-smoke" \
    "${OWNER_RPM}"
grep -Fxq 'pre:1' \
    "${DB_ROOT}/var/lib/tdnf-rpmzig-smoke/scriptlet"

run_as_root "${LIBEXEC}/tdnf-rpm-trigger" \
    --db-root "${DB_ROOT}" \
    --install-root "${DB_ROOT}" \
    --phase triggerin \
    --arg2 1 \
    --rpmdefine "_tmppath /var/lib/tdnf-rpmzig-smoke" \
    "${TARGET_RPM}"
grep -Fxq 'triggerin' \
    "${DB_ROOT}/var/lib/tdnf-rpmzig-smoke/trigger"

run_as_root "${LIBEXEC}/tdnf-rpm-erase" \
    --root "${DB_ROOT}" "${HNUM}"
[[ "$("${LIBEXEC}/tdnf-rpmdb-count" "${DB_ROOT}")" == "0" ]]
test ! -e "${DB_ROOT}/var/lib/tdnf-rpmzig-smoke/payload"

echo "All rpmzig smoke binaries passed"
