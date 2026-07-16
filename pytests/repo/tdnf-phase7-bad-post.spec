Summary: Phase 7 warning scriptlet fixture
Name: tdnf-phase7-bad-post
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Fails from a warning-only post-install scriptlet.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7
echo payload > %{buildroot}/usr/share/tdnf-phase7/bad-post

%post
exit 7

%files
/usr/share/tdnf-phase7/bad-post
