Summary:    helper package for transaction ordering tests
Name:       tdnf-native-order-helper
Version:    1.0
Release:    1
Vendor:     VMware, Inc.
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
Distribution:   Photon

%description
Helper package for transaction ordering tests.

%prep
%build
%install

mkdir -p %{buildroot}%{_bindir}
cat << 'EOF' > %{buildroot}%{_bindir}/tdnf-native-order-helper
#!/bin/sh
exit 0
EOF
chmod 0755 %{buildroot}%{_bindir}/tdnf-native-order-helper

%files
%{_bindir}/tdnf-native-order-helper

%changelog
