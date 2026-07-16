Summary: Phase 7 shared file-trigger path fixture A
Name: tdnf-phase7-filetarget-shared-a
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
First package in the native file-trigger shared directory fixture.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-shared/shared-dir
echo a > %{buildroot}/usr/share/tdnf-phase7-shared/shared-dir/a

%files
%dir /usr/share/tdnf-phase7-shared
%dir /usr/share/tdnf-phase7-shared/shared-dir
/usr/share/tdnf-phase7-shared/shared-dir/a
