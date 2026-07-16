Summary: Phase 7 invalid file-trigger query-format fixture
Name: tdnf-phase7-filetrigger-bad-query
Version: 1.0.0
Release: 1
License: MIT
BuildArch: noarch

%description
Contains an unsupported trigger query modifier for prevalidation tests.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/tdnf-phase7-filetrigger-bad-query
echo bad > %{buildroot}/usr/share/tdnf-phase7-filetrigger-bad-query/payload

%filetriggerin -q -- /usr/share/tdnf-phase7-filetarget
echo %%{NAME:not-a-format}

%files
/usr/share/tdnf-phase7-filetrigger-bad-query/payload
