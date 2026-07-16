Summary: Native RPM smoke-test fixture
Name: tdnf-rpmzig-smoke
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Exercises package parsing, payload installation, Lua scriptlets, triggers,
rpmdb writes, signature verification, and erasure.

%prep

%build

%install
mkdir -p %{buildroot}/var/lib/tdnf-rpmzig-smoke
echo payload > %{buildroot}/var/lib/tdnf-rpmzig-smoke/payload

%pre -p <lua>
local file = assert(io.open("/var/lib/tdnf-rpmzig-smoke/scriptlet", "w"))
file:write("pre:" .. tostring(arg[2]))
file:close()

%triggerin -p <lua> -- tdnf-rpmzig-smoke-target
local file = assert(io.open("/var/lib/tdnf-rpmzig-smoke/trigger", "w"))
file:write("triggerin")
file:close()

%files
/var/lib/tdnf-rpmzig-smoke/payload
