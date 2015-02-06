Name: @PACKAGE@
Summary: Secure Remote Log transmission system
Version: @VERSION@
Release: 2
License: GPL
Group: Utilities/System
Source: http://untroubled.org/@PACKAGE@/@PACKAGE@-@VERSION@.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
URL: http://untroubled.org/@PACKAGE@/
Packager: Bruce Guenter <bruce@untroubled.org>
BuildRequires: bglibs >= 2.02
BuildRequires: libtomcrypt-devel
BuildRequires: nistp224
Requires: libtomcrypt

%description
Secure Remote Log transmission system

%prep
%setup
#echo %{_libdir}/bglibs >conf-bglibs
#echo %{_includedir}/bglibs >conf-bgincs
echo %{_bindir} >conf-bin
echo %{_mandir} >conf-man
echo "gcc %{optflags}" >conf-cc
echo "gcc -s" >conf-ld
echo /etc/srlog2 >conf-etc

%build
make

%install
rm -fr %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}/etc/srlog2/env
mkdir -p %{buildroot}/etc/srlog2/servers

make install install_prefix=%{buildroot}

%clean
rm -rf %{buildroot}

%post
for key in nistp224 curve25519; do
  if ! [ -e /etc/srlog2/$key ]; then
    srlog2-keygen -t $key /etc/srlog2
  fi
done

%files
%defattr(-,root,root)
%dir /etc/srlog2
%dir /etc/srlog2/env
%dir /etc/srlog2/servers
%doc ANNOUNCEMENT COPYING NEWS README *.html curve25519-donna/LICENSE
%{_bindir}/*
%{_mandir}/*/*
