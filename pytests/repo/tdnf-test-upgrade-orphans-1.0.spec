#
# tdnf-test-upgrade-orphans spec file version 1.0
#
# Crosscheck spec for the native rpmzig transaction executor upgrade
# orphan-cleanup path. Version 1.0 ships:
#   /opt/tdnf-test-upgrade-orphans/shared     (kept by upgrade to 2.0)
#   /opt/tdnf-test-upgrade-orphans/old-only   (unique to 1.0)
#   /opt/tdnf-test-upgrade-orphans/nested/deep/old-only-nested
#
Summary:        tdnf native upgrade orphan-cleanup crosscheck package.
Name:           tdnf-test-upgrade-orphans
Version:        1.0
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
mkdir -p %{buildroot}/opt/tdnf-test-upgrade-orphans/nested/deep
echo shared-v1 > %{buildroot}/opt/tdnf-test-upgrade-orphans/shared
echo old-only  > %{buildroot}/opt/tdnf-test-upgrade-orphans/old-only
echo old-nest  > %{buildroot}/opt/tdnf-test-upgrade-orphans/nested/deep/old-only-nested

%files
/opt/tdnf-test-upgrade-orphans/shared
/opt/tdnf-test-upgrade-orphans/old-only
/opt/tdnf-test-upgrade-orphans/nested/deep/old-only-nested

%changelog
*   Mon Jul 13 2026 tdnf CI <tdnf-devel@vmware.com> 1.0-1
-   Initial crosscheck spec for native upgrade orphan cleanup.
