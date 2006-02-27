Name: @PACKAGE@
Summary: Secure Remote Log transmission system
Version: @VERSION@
Release: 2
License: GPL
Group: Utilities/System
Source: http://untroubled.org/@PACKAGE@/@PACKAGE@-@VERSION@.tar.gz
BuildRoot: %{_tmppath}/@PACKAGE@-buildroot
URL: http://untroubled.org/@PACKAGE@/
Packager: Bruce Guenter <bruce@untroubled.org>
BuildRequires: bglibs >= 1.041
BuildRequires: libtomcrypt

%description
Secure Remote Log transmission system

%prep
%setup
#echo gcc -I/usr/local/bglibs/include "%{optflags}" >conf-cc
#echo gcc -L/usr/local/bglibs/lib -s >conf-ld
echo %{_bindir} >conf-bin

%build
make

%install
rm -fr %{buildroot}
mkdir -p %{buildroot}%{_bindir}

make install install_prefix=$RPM_BUILD_ROOT

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc ANNOUNCEMENT COPYING NEWS README *.html
%{_bindir}/*
