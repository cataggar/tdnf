Summary:    Requires(preun) ordering test package
Name:       tdnf-native-order-preun
Version:    1.0
Release:    1
Vendor:     VMware, Inc.
License:    VMware
Url:        http://www.vmware.com
Group:      Applications/tdnftest
Distribution:   Photon
Requires(preun): /usr/bin/tdnf-native-order-helper

%description
Exercise Requires(preun) ordering.

%prep
%build
%install

mkdir -p %{buildroot}%{_datadir}/tdnf-native-order
echo preun > %{buildroot}%{_datadir}/tdnf-native-order/preun

%preun -p <lua>
local helper = io.open("%{_bindir}/tdnf-native-order-helper", "r")
if helper == nil then
    error("transaction provider was erased before dependent erase script")
end
helper:close()

%files
%{_datadir}/tdnf-native-order/preun

%changelog
