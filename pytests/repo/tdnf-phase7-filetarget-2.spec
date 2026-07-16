Summary: Phase 7 native file trigger target v2
Name: tdnf-phase7-filetarget
Version: 2.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Version two of the native file trigger target.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetarget
echo common-v2 > %{buildroot}/usr/share/tdnf-phase7-filetarget/common
echo v2 > %{buildroot}/usr/share/tdnf-phase7-filetarget/v2-only

%pre
echo target-v2-pre:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%post
echo target-v2-post:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%preun
echo target-v2-preun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%postun
echo target-v2-postun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%posttrans
echo target-v2-posttrans:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%files
/usr/share/tdnf-phase7-filetarget/common
/usr/share/tdnf-phase7-filetarget/v2-only
