Summary: Phase 7 second native transaction file trigger owner
Name: tdnf-phase7-filetrigger-owner-second
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Provides a second owner whose priorities expose incorrect global sorting of
immediate transaction file triggers.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-owner-second
echo owner > %{buildroot}/usr/share/tdnf-phase7-filetrigger-owner-second/payload

%post
echo owner-second-post:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%preun
echo owner-second-preun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%transfiletriggerin -P 400000 -- /usr/share/tdnf-phase7-filetarget
echo trans-second-in-p400000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerin -P 50 -- /usr/share/tdnf-phase7-filetarget
echo trans-second-in-p50:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerun -P 400000 -- /usr/share/tdnf-phase7-filetarget
echo trans-second-un-p400000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerun -P 50 -- /usr/share/tdnf-phase7-filetarget
echo trans-second-un-p50:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%files
/usr/share/tdnf-phase7-filetrigger-owner-second/payload
