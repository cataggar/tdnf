Summary: Phase 7 added file trigger owner visibility fixture
Name: tdnf-phase7-filetrigger-added-owner
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch
Obsoletes: tdnf-phase7-filetarget < 9

%description
An owner added by the same transaction that removes its obsolete target.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-added-owner
echo owner > %{buildroot}/usr/share/tdnf-phase7-filetrigger-added-owner/payload

%filetriggerun -P 200000 -- /usr/share/tdnf-phase7-filetarget
echo visibility-added-un:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo visibility-added-un-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%files
/usr/share/tdnf-phase7-filetrigger-added-owner/payload
