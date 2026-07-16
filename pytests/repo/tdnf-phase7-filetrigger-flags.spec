Summary: Phase 7 native file trigger flags fixture
Name: tdnf-phase7-filetrigger-flags
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Exercises runtime macro expansion, queryformat expansion, and Lua argument
handling for package and transaction file triggers.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-flags
echo flags > %{buildroot}/usr/share/tdnf-phase7-filetrigger-flags/payload

%filetriggerin -P 250000 -e -- /usr/share/tdnf-phase7-filetarget
echo flags-expand:%%{_dbpath}:$#:$1:${2-unset} >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%filetriggerin -P 240000 -q -- /usr/share/tdnf-phase7-filetarget
echo flags-query:%%{NAME}:%%{VERSION}:%%{ARCH}:$#:$1 >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%filetriggerin -P 235000 -q -- /usr/share/tdnf-phase7-filetarget
qformat_name=%%{NAME:shescape}
echo qformat-modifiers:$qformat_name:%%{BUILDTIME:hex}:%%{BUILDTIME:octal}:%%{BASENAMES:arraysize}:%%{FILEMODES:perms}:%%{FILEFLAGS:fflags} >> /var/lib/tdnf-phase7-filetriggers.log
echo "qformat-date:%%{INSTALLTIME:date}|%%{INSTALLTIME:day}" >> /var/lib/tdnf-phase7-filetriggers.log
echo "qformat-width:<%%-36{NAME}>" >> /var/lib/tdnf-phase7-filetriggers.log
echo qformat-conditional:%|EPOCH?{epoch=%%{EPOCH}}:{%|NAME?{noepoch-%%{NAME}}:{missing}|}| >> /var/lib/tdnf-phase7-filetriggers.log
[echo qformat-iterator:%%{=NAME}:%%{FILENAMES}:%%{FILEMODES:perms}:%%{FILEFLAGS:fflags} >> /var/lib/tdnf-phase7-filetriggers.log\n]
while IFS= read -r path; do :; done

%filetriggerin -P 230000 -p <lua> -- /usr/share/tdnf-phase7-filetarget
local log = assert(io.open("/var/lib/tdnf-phase7-filetriggers.log", "a"))
log:write("flags-lua:" .. tostring(#arg) .. ":" ..
          tostring(arg[2]) .. ":" .. tostring(arg[3]) .. "\n")
local next_path = rpm.next_file or rpm.input
while true do
    local path = next_path()
    if path == nil then break end
end
log:close()

%transfiletriggerin -P 220000 -e -q -- /usr/share/tdnf-phase7-filetarget
echo flags-trans:%%{_dbpath}:%%{NAME}:$#:$1 >> /var/lib/tdnf-phase7-filetriggers.log
while IFS= read -r path; do :; done

%files
/usr/share/tdnf-phase7-filetrigger-flags/payload
