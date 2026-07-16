Summary: Phase 7 native file trigger owner fixture
Name: tdnf-phase7-filetrigger-owner
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Owns ordered package and transaction file triggers used by the native
transaction executor end-to-end tests.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-owner
echo owner > %{buildroot}/usr/share/tdnf-phase7-filetrigger-owner/payload

%post
echo owner-post:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%preun
echo owner-preun:$1 >> /var/lib/tdnf-phase7-filetriggers.log

%filetriggerin -P 200000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/common
echo file-in-p200000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo file-in-p200000-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%filetriggerin -P 100000 -- /usr/share/tdnf-phase7-filetarget
echo file-in-p100000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%filetriggerin -P 100 -- /usr/share/tdnf-phase7-filetarget
echo file-in-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%filetriggerun -P 200000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/v1-only
echo file-un-p200000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo file-un-p200000-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%filetriggerun -P 100 -- /usr/share/tdnf-phase7-filetarget
echo file-un-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%filetriggerpostun -P 200000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/v1-only
echo file-postun-p200000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo file-postun-p200000-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%filetriggerpostun -P 100 -- /usr/share/tdnf-phase7-filetarget
echo file-postun-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerin -P 300000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/common
echo trans-in-p300000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo trans-in-p300000-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%transfiletriggerin -P 100 -- /usr/share/tdnf-phase7-filetarget
echo trans-in-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerun -P 300000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/v1-only
echo trans-un-p300000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo trans-un-p300000-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%transfiletriggerun -P 100 -- /usr/share/tdnf-phase7-filetarget
echo trans-un-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%transfiletriggerpostun -P 300000 -- /usr/share/tdnf-phase7-filetarget /usr/share/tdnf-phase7-filetarget/v1-only
echo trans-postun-p300000:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
if IFS= read -r path; then
    echo trans-postun-unexpected-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
fi

%transfiletriggerpostun -P 100 -- /usr/share/tdnf-phase7-filetarget
echo trans-postun-p100:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
if IFS= read -r path; then :; fi

%filetriggerin -P 210000 -- /usr/share/tdnf-phase7-shared /usr/share/tdnf-phase7-shared/shared-dir
echo shared-in:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do
    echo shared-in-path:$path >> /var/lib/tdnf-phase7-filetriggers.log
done

%files
/usr/share/tdnf-phase7-filetrigger-owner/payload
