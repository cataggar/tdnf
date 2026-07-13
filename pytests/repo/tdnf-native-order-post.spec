Summary:    Requires(post) ordering test package
Name:       tdnf-native-order-post
Version:    1.0
Release:    1
Vendor:     VMware, Inc.
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
Distribution:   Photon
Requires(post): /usr/bin/tdnf-native-order-helper

%description
Exercise Requires(post) ordering.

%prep
%build
%install

mkdir -p %{buildroot}%{_datadir}/tdnf-native-order
echo post > %{buildroot}%{_datadir}/tdnf-native-order/post

%post
test -x %{_bindir}/tdnf-native-order-helper

%files
%{_datadir}/tdnf-native-order/post

%changelog
