Summary: Phase 7 shared file-trigger path fixture B
Name: tdnf-phase7-filetarget-shared-b
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Second package in the native file-trigger shared directory fixture.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-shared/shared-dir
echo b > %{buildroot}/usr/share/tdnf-phase7-shared/shared-dir/b

%files
%dir /usr/share/tdnf-phase7-shared
%dir /usr/share/tdnf-phase7-shared/shared-dir
/usr/share/tdnf-phase7-shared/shared-dir/b
