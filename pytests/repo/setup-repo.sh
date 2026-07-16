#!/bin/bash
#
# Copyright (C) 2020-2023 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU Lesser General Public License v2.1 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#

if [ $# -ne 2 ]; then
    echo "Usage: $0 <repo_path> <specs_dir>" >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
METALINK_FIXTURE=${SCRIPT_DIR}/../fixtures/metalink/photon-setup.xml
CALLER_HOME=${HOME}
CALLER_RPMMACROS=${CALLER_HOME}/.rpmmacros
if [ -f "${CALLER_RPMMACROS}" ]; then
  CALLER_RPMMACROS_STATE=$(cksum < "${CALLER_RPMMACROS}")
else
  CALLER_RPMMACROS_STATE=missing
fi

function verify_caller_rpmmacros() {
  local current=missing
  if [ -f "${CALLER_RPMMACROS}" ]; then
    current=$(cksum < "${CALLER_RPMMACROS}")
  fi
  if [ "${current}" != "${CALLER_RPMMACROS_STATE}" ]; then
    echo "ERROR: setup-repo modified ${CALLER_RPMMACROS}" >&2
    return 1
  fi
}
trap verify_caller_rpmmacros EXIT

function fix_dir_perms() {
  chmod 755 ${TEST_REPO_DIR}
  find ${TEST_REPO_DIR} -type d -exec chmod 0755 {} \;
  find ${TEST_REPO_DIR} -type f -exec chmod 0644 {} \;
}

function save_mutable_baseline() {
  local baseline=${TEST_REPO_DIR}/.baseline
  rm -rf "${baseline}"
  mkdir -p "${baseline}"
  cp "${TEST_REPO_DIR}/tdnf.conf" "${baseline}/tdnf.conf"
  cp -a "${TEST_REPO_DIR}/yum.repos.d" "${baseline}/yum.repos.d"
  cp "${TEST_REPO_DIR}/photon-test/metalink" "${baseline}/metalink"
}

function restore_mutable_baseline() {
  local baseline=${TEST_REPO_DIR}/.baseline
  cp "${baseline}/tdnf.conf" "${TEST_REPO_DIR}/tdnf.conf"
  rm -rf "${TEST_REPO_DIR}/yum.repos.d"
  cp -a "${baseline}/yum.repos.d" "${TEST_REPO_DIR}/yum.repos.d"
  cp "${baseline}/metalink" "${TEST_REPO_DIR}/photon-test/metalink"
  rm -rf "${TEST_REPO_DIR}/vars" "${TEST_REPO_DIR}/pluginconf.d"
}

## used to check return code for each command.
function check_err() {
  local rc=$?
  if [ $rc -ne 0 ]; then
      echo "$1" >&2
      exit $rc
  fi
}

TEST_REPO_DIR=$1
if [ -d ${TEST_REPO_DIR} ]; then
    if [ -d "${TEST_REPO_DIR}/.baseline" ]; then
        echo "Repo already exists"
        restore_mutable_baseline
        fix_dir_perms
        exit 0
    fi
    echo "Repo has no pristine baseline; rebuilding"
    rm -rf "${TEST_REPO_DIR}"
fi

REPO_SRC_DIR=$2
if [ ! -d ${REPO_SRC_DIR} ]; then
    echo "ERROR: specs dir does not exist" >&2
    exit 1
fi

export GNUPGHOME=${TEST_REPO_DIR}/gnupg

BUILD_PATH=${TEST_REPO_DIR}/build
PUBLISH_PATH=${TEST_REPO_DIR}/photon-test
PUBLISH_SRC_PATH=${TEST_REPO_DIR}/photon-test-src
PUBLISH_SHA512_PATH=${TEST_REPO_DIR}/photon-test-sha512
PUBLISH_UNSIGNED_PATH=${TEST_REPO_DIR}/photon-test-unsigned

ARCH=$(uname -m)

mkdir -p -m 755 ${BUILD_PATH}/BUILD \
    ${BUILD_PATH}/SOURCES \
    ${BUILD_PATH}/SRPMS \
    ${BUILD_PATH}/RPMS/${ARCH} \
    ${BUILD_PATH}/RPMS/noarch \
    ${TEST_REPO_DIR}/yum.repos.d \
    ${PUBLISH_PATH} \
    ${PUBLISH_SRC_PATH} \
    ${PUBLISH_SHA512_PATH} \
    ${PUBLISH_UNSIGNED_PATH} \
    ${GNUPGHOME}

mkdir -p "${TEST_REPO_DIR}/home"
export HOME=${TEST_REPO_DIR}/home

#gpgkey data for unattended key generation
cat << EOF > ${TEST_REPO_DIR}/gpgkeydata
%echo Generating a key for repogpgcheck signatures
%no-protection
Key-Type: RSA
Subkey-Type: RSA
Name-Real: tdnf test
Name-Comment: tdnf test key
Name-Email: tdnftest@tdnf.test
Expire-Date: 0
%commit
%echo done
EOF

#generate a key non interactively. this is used in testing
#repogpgcheck plugin
gpg --batch --generate-key ${TEST_REPO_DIR}/gpgkeydata
check_err "Failed to generate gpg key."

for d in conflicts enhances obsoletes provides recommends requires suggests supplements ; do
    sed s/@@dep@@/$d/ < ${REPO_SRC_DIR}/tdnf-repoquery-deps.spec.in > ${BUILD_PATH}/SOURCES/tdnf-repoquery-$d.spec
done

echo "Building packages"
for spec in ${REPO_SRC_DIR}/*.spec ${BUILD_PATH}/SOURCES/*.spec ; do
    echo "Building ${spec}"
    rpmbuild \
      -D "_topdir ${BUILD_PATH}" \
      -D "__transaction_unshare %{nil}" \
      -ba ${spec} 2>&1
    check_err "ERROR: failed to build ${spec}"
done
cp -r ${BUILD_PATH}/RPMS ${PUBLISH_UNSIGNED_PATH}
rpmsign \
  --define "_gpg_name tdnftest@tdnf.test" \
  --define "__gpg /usr/bin/gpg" \
  --define "__transaction_unshare %{nil}" \
  --addsign ${BUILD_PATH}/RPMS/*/*.rpm
check_err "Failed to sign built packages."
cp -r ${BUILD_PATH}/RPMS ${PUBLISH_PATH}
cp -r ${BUILD_PATH}/SRPMS ${PUBLISH_SRC_PATH}
cp -r ${BUILD_PATH}/RPMS ${PUBLISH_SHA512_PATH}

# save key to later be imported:
mkdir -p ${PUBLISH_PATH}/keys
gpg --armor --export tdnftest@tdnf.test > ${PUBLISH_PATH}/keys/pubkey.asc

gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: tdnf test wrong
Name-Email: tdnftest@tdnf.wrong
Expire-Date: 0
%no-protection
%commit
EOF

WRONG_FPR=$(gpg --list-keys --with-colons tdnftest@tdnf.wrong | awk -F: '/^fpr:/ {print $10; exit}')
gpg --armor --export "${WRONG_FPR}" > ${PUBLISH_PATH}/keys/pubkey.wrong.asc

createrepo ${PUBLISH_PATH}
createrepo ${PUBLISH_SRC_PATH}
createrepo -s sha512 ${PUBLISH_SHA512_PATH}
createrepo ${PUBLISH_UNSIGNED_PATH}

modifyrepo ${REPO_SRC_DIR}/updateinfo-1.xml ${PUBLISH_PATH}/repodata
check_err "Failed to modify repo with updateinfo-1.xml."
modifyrepo ${REPO_SRC_DIR}/updateinfo-2.xml ${PUBLISH_PATH}/repodata
check_err "Failed to modify repo with updateinfo-2.xml."

#gpg sign repomd.xml
gpg --batch --passphrase-fd 0 \
--pinentry-mode loopback \
--detach-sign --armor ${PUBLISH_PATH}/repodata/repomd.xml
check_err "Failed to gpg sign repomd.xml."

cat << EOF > ${TEST_REPO_DIR}/yum.repos.d/photon-test.repo
[photon-test]
name=basic
baseurl=http://localhost:8080/photon-test
#metalink=http://localhost:8080/photon-test/metalink
gpgkey=file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY
gpgcheck=0
enabled=1
EOF

cat << EOF > ${TEST_REPO_DIR}/yum.repos.d/photon-test-auth.repo
[photon-test-auth]
name=basic
baseurl=http://localhost:8088/photon-test
gpgkey=file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY
gpgcheck=0
enabled=0
username=cassian
password=andor
EOF

cat << EOF > ${TEST_REPO_DIR}/yum.repos.d/photon-test-unsigned.repo
[photon-test-unsigned]
name=basic
baseurl=http://localhost:8080/photon-test-unsigned
gpgcheck=0
enabled=0
EOF

cat << EOF > ${TEST_REPO_DIR}/yum.repos.d/photon-test-sha512.repo
[photon-test-sha512]
name=basic
baseurl=http://localhost:8080/photon-test-sha512
#metalink=http://localhost:8080/photon-test-sha512/metalink
gpgkey=file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY
gpgcheck=0
enabled=0
EOF

cat << EOF > ${TEST_REPO_DIR}/yum.repos.d/photon-test-src.repo
[photon-test-src]
name=basic
baseurl=http://localhost:8080/photon-test-src
gpgkey=file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY
gpgcheck=0
enabled=0
EOF

cat << EOF > ${TEST_REPO_DIR}/tdnf.conf
[main]
gpgcheck=0
installonly_limit=3
clean_requirements_on_remove=true
repodir=${TEST_REPO_DIR}/yum.repos.d
cachedir=${TEST_REPO_DIR}/cache/tdnf
EOF

cat "${METALINK_FIXTURE}" > "${PUBLISH_PATH}/metalink"
check_err "Failed to install metalink fixture."

save_mutable_baseline
fix_dir_perms
