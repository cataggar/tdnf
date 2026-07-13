Summary:    Requires(pre) ordering test package
Name:       tdnf-native-order-pre
Version:    1.0
Release:    1
Vendor:     VMware, Inc.
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
Distribution:   Photon
Requires(pre): /usr/bin/tdnf-native-order-helper

%description
Exercise Requires(pre) ordering.

%prep
%build
%install

mkdir -p %{buildroot}%{_datadir}/tdnf-native-order
echo pre > %{buildroot}%{_datadir}/tdnf-native-order/pre

%pre
test -x %{_bindir}/tdnf-native-order-helper

%files
%{_datadir}/tdnf-native-order/pre

%changelog
