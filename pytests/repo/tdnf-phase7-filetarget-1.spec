Summary: Phase 7 native file trigger target v1
Name: tdnf-phase7-filetarget
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Version one of the native file trigger target.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetarget
echo common-v1 > %{buildroot}/usr/share/tdnf-phase7-filetarget/common
echo v1 > %{buildroot}/usr/share/tdnf-phase7-filetarget/v1-only

%pre
echo target-v1-pre:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%post
echo target-v1-post:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%preun
echo target-v1-preun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%postun
echo target-v1-postun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%posttrans
echo target-v1-posttrans:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%filetriggerpostun -P 150000 -- /usr/share/tdnf-phase7-filetarget/v1-only
echo target-v1-self-postun:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo target-v1-self-postun-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%files
/usr/share/tdnf-phase7-filetarget/common
/usr/share/tdnf-phase7-filetarget/v1-only
