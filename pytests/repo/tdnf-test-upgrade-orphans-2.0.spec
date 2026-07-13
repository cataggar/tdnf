#
# tdnf-test-upgrade-orphans spec file version 2.0
#
# Crosscheck spec for the native rpmzig transaction executor upgrade
# orphan-cleanup path. Version 2.0 ships:
#   /opt/tdnf-test-upgrade-orphans/shared     (also in 1.0 -> preserved)
#   /opt/tdnf-test-upgrade-orphans/new-only   (unique to 2.0)
#
# Files unique to 1.0 (old-only, nested/deep/old-only-nested) must be
# removed by the upgrade path.
#
Summary:        tdnf native upgrade orphan-cleanup crosscheck package.
Name:           tdnf-test-upgrade-orphans
Version:        2.0
Release:        1
Vendor:         VMware, Inc.
Distribution:   Photon
License:        VMware
Url:            http://www.vmware.com
Group:          Applications/tdnftest

%description
Part of tdnf test spec. Exercises the upgrade file-erase path.

%prep

%build

%install
mkdir -p %{buildroot}/opt/tdnf-test-upgrade-orphans
echo shared-v2 > %{buildroot}/opt/tdnf-test-upgrade-orphans/shared
echo new-only  > %{buildroot}/opt/tdnf-test-upgrade-orphans/new-only

%files
/opt/tdnf-test-upgrade-orphans/shared
/opt/tdnf-test-upgrade-orphans/new-only

%changelog
*   Mon Jul 13 2026 tdnf CI <tdnf-devel@vmware.com> 2.0-1
-   Second version drops old-only files.
