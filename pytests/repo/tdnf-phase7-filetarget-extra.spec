Summary: Phase 7 native transaction file trigger extra target
Name: tdnf-phase7-filetarget-extra
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Second package used to prove transaction file triggers execute once.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetarget
echo extra > %{buildroot}/usr/share/tdnf-phase7-filetarget/extra

%files
/usr/share/tdnf-phase7-filetarget/extra
