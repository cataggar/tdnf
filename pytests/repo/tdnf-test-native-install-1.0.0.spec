#
# tdnf-test-native-install 1.0.0 spec file
#
Summary:    native rpmzig file-installation crosscheck fixture.
Name:       tdnf-test-native-install
Version:    1.0.0
Release:    1
Vendor:     VMware, Inc.
Distribution:   Photon
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
BuildArch:  noarch

%description
Part of tdnf test fixtures. Exercises native file installation semantics.

%prep

%build

%install
mkdir -p %{buildroot}/etc/%{name}
mkdir -p %{buildroot}/usr/share/%{name}
mkdir -p %{buildroot}/usr/share/doc/%{name}
mkdir -p %{buildroot}/usr/share/licenses/%{name}

echo 'plain-config-v1' > %{buildroot}/etc/%{name}/plain.conf
echo 'noreplace-config-v1' > %{buildroot}/etc/%{name}/noreplace.conf
echo 'plain-file-v1' > %{buildroot}/usr/share/%{name}/plain.txt
echo 'hardlink-payload-v1' > %{buildroot}/usr/share/%{name}/hardlink-a
ln %{buildroot}/usr/share/%{name}/hardlink-a %{buildroot}/usr/share/%{name}/hardlink-b
echo 'doc-v1' > %{buildroot}/usr/share/doc/%{name}/README
echo 'license-v1' > %{buildroot}/usr/share/licenses/%{name}/LICENSE

touch -d '@1700000000' %{buildroot}/etc/%{name}/plain.conf
touch -d '@1700000000' %{buildroot}/etc/%{name}/noreplace.conf
touch -d '@1700000000' %{buildroot}/usr/share/%{name}/plain.txt
touch -d '@1700000000' %{buildroot}/usr/share/%{name}/hardlink-a
touch -d '@1700000000' %{buildroot}/usr/share/doc/%{name}/README
touch -d '@1700000000' %{buildroot}/usr/share/licenses/%{name}/LICENSE

%files
%config /etc/%{name}/plain.conf
%config(noreplace) /etc/%{name}/noreplace.conf
/usr/share/%{name}/plain.txt
/usr/share/%{name}/hardlink-a
/usr/share/%{name}/hardlink-b
%doc /usr/share/doc/%{name}/README
%license /usr/share/licenses/%{name}/LICENSE
%ghost /var/lib/%{name}/ghost.token

%changelog
*   Mon Jul 14 2026 Cameron Taggart <cataggar@users.noreply.github.com> 1.0.0-1
-   Initial native install fixture.
