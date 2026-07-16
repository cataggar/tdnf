Summary: Phase 7 trigger target fixture
Name: tdnf-phase7-trigger-target
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Target package for native transaction trigger flag tests.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7
echo target > %{buildroot}/usr/share/tdnf-phase7/trigger-target

%files
/usr/share/tdnf-phase7/trigger-target
