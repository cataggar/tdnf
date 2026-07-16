Summary: Phase 7 removed file trigger owner visibility fixture
Name: tdnf-phase7-filetrigger-removed-owner
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
An installed owner removed by the same transaction that adds its target.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-removed-owner
echo owner > %{buildroot}/usr/share/tdnf-phase7-filetrigger-removed-owner/payload

%filetriggerin -P 200000 -- /usr/share/tdnf-phase7-filetarget-replacement
echo visibility-removed-in:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo visibility-removed-in-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%files
/usr/share/tdnf-phase7-filetrigger-removed-owner/payload
