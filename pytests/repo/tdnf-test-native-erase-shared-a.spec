#
# tdnf-test-native-erase-shared-a spec file
#
Summary:    native rpmzig file-erase shared-ownership fixture A.
Name:       tdnf-test-native-erase-shared-a
Version:    1.0.0
Release:    1
Vendor:     VMware, Inc.
Distribution:   Photon
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
BuildArch:  noarch

%description
Part of tdnf test fixtures. Exercises native file erase shared ownership.

%prep

%build

%install
mkdir -p %{buildroot}/etc/tdnf-test-native-erase-shared
mkdir -p %{buildroot}/usr/share/tdnf-test-native-erase-shared/shared-dir

echo 'shared-config' > %{buildroot}/etc/tdnf-test-native-erase-shared/shared.conf
echo 'shared-a' > %{buildroot}/usr/share/tdnf-test-native-erase-shared/shared-dir/a.txt

touch -d '@1700200000' %{buildroot}/etc/tdnf-test-native-erase-shared/shared.conf
touch -d '@1700200000' %{buildroot}/usr/share/tdnf-test-native-erase-shared/shared-dir
touch -d '@1700200000' %{buildroot}/usr/share/tdnf-test-native-erase-shared/shared-dir/a.txt

%files
%config(noreplace) /etc/tdnf-test-native-erase-shared/shared.conf
%dir /usr/share/tdnf-test-native-erase-shared/shared-dir
/usr/share/tdnf-test-native-erase-shared/shared-dir/a.txt

%changelog
*   Mon Jul 14 2026 Cameron Taggart <cataggar@users.noreply.github.com> 1.0.0-1
-   Initial native file erase shared-ownership fixture A.
