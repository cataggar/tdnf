Summary: Phase 7 trigger owner fixture
Name: tdnf-phase7-trigger-owner
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Records every trigger phase fired by the Phase 7 target package.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7
echo owner > %{buildroot}/usr/share/tdnf-phase7/trigger-owner

%triggerin -- tdnf-phase7-trigger-target
echo triggerin:$1:$2 >> /var/tmp/tdnf-phase7-triggers.log

%triggerun -- tdnf-phase7-trigger-target
echo triggerun:$1:$2 >> /var/tmp/tdnf-phase7-triggers.log

%triggerpostun -- tdnf-phase7-trigger-target
echo triggerpostun:$1:$2 >> /var/tmp/tdnf-phase7-triggers.log

%files
/usr/share/tdnf-phase7/trigger-owner
