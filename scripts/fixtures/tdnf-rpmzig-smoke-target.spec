Summary: Native RPM trigger target
Name: tdnf-rpmzig-smoke-target
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Minimal target package for the native trigger smoke test.

%prep

%build

%install
mkdir -p %{buildroot}/var/lib/tdnf-rpmzig-smoke
echo target > %{buildroot}/var/lib/tdnf-rpmzig-smoke/target

%files
/var/lib/tdnf-rpmzig-smoke/target
