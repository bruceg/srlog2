Name: @PACKAGE@
Summary: FutureQuest log send/receive system
Version: @VERSION@
Release: 2
Copyright: Proprietary
Group: Utilities/System
Source: http://untroubled.org/@PACKAGE@/@PACKAGE@-@VERSION@.tar.gz
BuildRoot: %{_tmppath}/@PACKAGE@-buildroot
URL: http://untroubled.org/@PACKAGE@/
Packager: Bruce Guenter <Bruce@FutureQuest.net>
BuildRequires: bglibs >= 1.010

%description
FutureQuest log send/receive system

%prep
%setup
#echo gcc -I/usr/local/bglibs/include "%{optflags}" >conf-cc
#echo gcc -L/usr/local/bglibs/lib -s >conf-ld
echo %{_bindir} >conf-bin

%build
make

%install
rm -fr %{buildroot}
rm -f conf_bin.c insthier.o installer instcheck
echo %{buildroot}%{_bindir} >conf-bin
make installer instcheck

mkdir -p %{buildroot}%{_bindir}
./installer
./instcheck

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc ANNOUNCEMENT COPYING NEWS README *.html
%{_bindir}/*
