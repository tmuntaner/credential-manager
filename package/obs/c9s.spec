Name:           c9s
Version:        0.1.0
Release:        0
Summary:        A cloud credential manager
License:        MIT
URL:            https://github.com/Firstyear/kanidm
Source:         c9s-%{version}.tar.bz2
Source1:        vendor.tar.bz2
Source2:        cargo.config
BuildRequires:  cargo-packaging
BuildRequires:  cargo >= 1.52.1
BuildRequires:  libudev-devel
BuildRequires:  openssl-devel
BuildRequires:  dbus-1-devel
Group:          Productivity/Security

%description
c9s is cloud credential manager.

Currently, it supports generating temporary AWS credentials from Okta.

%prep
%setup -q
%setup -qa1
mkdir .cargo
cp %{SOURCE2} .cargo/config

%build
%{cargo_build}

%install
install -D -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_builddir}/%{name}-%{version}/target/release/c9s %{buildroot}%{_bindir}/c9s

%files
%defattr(-,root,root)
%{_bindir}/c9s

%changelog
