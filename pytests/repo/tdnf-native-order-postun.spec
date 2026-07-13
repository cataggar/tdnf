Summary:    Requires(postun) ordering test package
Name:       tdnf-native-order-postun
Version:    1.0
Release:    1
Vendor:     VMware, Inc.
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
Distribution:   Photon
Requires(postun): /usr/bin/tdnf-native-order-helper

%description
Exercise Requires(postun) ordering.

%prep
%build
%install

mkdir -p %{buildroot}%{_datadir}/tdnf-native-order
echo postun > %{buildroot}%{_datadir}/tdnf-native-order/postun

%postun
test -x %{_bindir}/tdnf-native-order-helper

%files
%{_datadir}/tdnf-native-order/postun

%changelog
