Summary: Phase 7 removed trigger owner replacement target
Name: tdnf-phase7-filetarget-replacement
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch
Obsoletes: tdnf-phase7-filetrigger-removed-owner < 9

%description
Adds a matching path while obsoleting an installed file trigger owner.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetarget-replacement
echo target > %{buildroot}/usr/share/tdnf-phase7-filetarget-replacement/payload

%files
/usr/share/tdnf-phase7-filetarget-replacement/payload
