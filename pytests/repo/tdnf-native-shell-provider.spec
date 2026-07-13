Name:       tdnf-native-shell-provider
Version:    1.0
Release:    1
Summary:    Provides /bin/sh for native transaction tests
License:    LGPLv2.1
BuildArch:  noarch
Provides:   /bin/sh

%description
Provides /bin/sh so native transaction tests can build local rpmdb fixtures
without depending on the host rpmdb.

%install
mkdir -p %{buildroot}/usr/share/tdnf-native
echo shell-provider > %{buildroot}/usr/share/tdnf-native/shell-provider

%files
/usr/share/tdnf-native/shell-provider
