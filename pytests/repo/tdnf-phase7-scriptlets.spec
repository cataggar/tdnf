Summary: Phase 7 transaction scriptlet fixture
Name: tdnf-phase7-scriptlets
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Records every package and transaction scriptlet phase.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7
echo payload > %{buildroot}/usr/share/tdnf-phase7/scriptlets

%pretrans
echo pretrans:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%pre
echo pre:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%post
echo post:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%preun
echo preun:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%postun
echo postun:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%posttrans
echo posttrans:$1 >> /var/tmp/tdnf-phase7-scriptlets.log

%files
/usr/share/tdnf-phase7/scriptlets
