%global frr_libdir %{_libexecdir}/frr

%global _hardened_build 1
%define _legacy_common_support 1
%global selinuxtype targeted
%bcond_without selinux

Name: frr
Version: 8.3.1
Release: 11%{?checkout}%{?dist}
Summary: Routing daemon
License: GPLv2+
URL: http://www.frrouting.org
Source0: https://github.com/FRRouting/frr/releases/download/%{name}-%{version}/%{name}-%{version}.tar.gz
Source1: %{name}-tmpfiles.conf
Source2: frr-sysusers.conf
Source3: frr.fc
Source4: frr.te
Source5: frr.if
Source6: remove-babeld-ldpd.sh
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  bison >= 2.7
BuildRequires:  c-ares-devel
BuildRequires:  flex
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  git-core
BuildRequires:  groff
BuildRequires:  json-c-devel
BuildRequires:  libcap-devel
BuildRequires:  libtool
BuildRequires:  libyang-devel >= 2.0.0
BuildRequires:  make
BuildRequires:  ncurses
BuildRequires:  ncurses-devel
BuildRequires:  net-snmp-devel
BuildRequires:  pam-devel
BuildRequires:  patch
BuildRequires:  perl-XML-LibXML
BuildRequires:  perl-generators
BuildRequires:  python3-devel
BuildRequires:  python3-pytest
BuildRequires:  python3-sphinx
BuildRequires:  readline-devel
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  texinfo

Requires: net-snmp
Requires: ncurses
Requires(post): systemd
Requires(post): /sbin/install-info
Requires(post): hostname
Requires(preun): systemd
Requires(preun): /sbin/install-info
Requires(postun): systemd

%if 0%{?with_selinux}
Requires: (%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})
%endif

Conflicts: quagga
Provides: routingdaemon = %{version}-%{release}

Patch0000: 0000-remove-babeld-and-ldpd.patch
Patch0002: 0002-enable-openssl.patch
Patch0003: 0003-disable-eigrp-crypto.patch
Patch0004: 0004-fips-mode.patch
Patch0005: 0005-ospf-api.patch
Patch0006: 0006-graceful-restart.patch
Patch0007: 0007-cve-2022-37032.patch
Patch0008: 0008-frr-non-root-user.patch
Patch0009: 0009-CVE-2022-36440-40302.patch
Patch0010: 0010-CVE-2022-43681.patch
Patch0011: 0011-CVE-2022-40318.patch
Patch0012: 0012-bfd-not-working-in-vrf.patch
Patch0013: 0013-CVE-2023-38802.patch

%description
FRRouting is free software that manages TCP/IP based routing protocols. It takes
a multi-server and multi-threaded approach to resolve the current complexity
of the Internet.

FRRouting supports BGP4, OSPFv2, OSPFv3, ISIS, RIP, RIPng, PIM, NHRP, PBR, EIGRP and BFD.

FRRouting is a fork of Quagga.

%if 0%{?with_selinux}
%package selinux
Summary:        Selinux policy for FRR
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
BuildRequires:  selinux-policy-devel
%{?selinux_requires}

%description selinux
SELinux policy modules for FRR package

%endif

%prep
%autosetup -S git
mkdir selinux
cp -p %{SOURCE3} %{SOURCE4} %{SOURCE5} selinux

%build
autoreconf -ivf

%configure \
    --sbindir=%{frr_libdir} \
    --sysconfdir=%{_sysconfdir}/frr \
    --libdir=%{_libdir}/frr \
    --libexecdir=%{_libexecdir}/frr \
    --localstatedir=%{_localstatedir}/run/frr \
    --enable-multipath=64 \
    --enable-vtysh=yes \
    --disable-ospfclient \
    --disable-ospfapi \
    --enable-snmp=agentx \
    --enable-user=frr \
    --enable-group=frr \
    --enable-vty-group=frrvty \
    --enable-rtadv \
    --disable-exampledir \
    --enable-systemd=yes \
    --enable-static=no \
    --disable-ldpd \
    --disable-babeld \
    --with-moduledir=%{_libdir}/frr/modules \
    --with-crypto=openssl \
    --enable-fpm

%make_build MAKEINFO="makeinfo --no-split" PYTHON=%{__python3}

pushd doc
make info
popd

%if 0%{?with_selinux}
make -C selinux -f %{_datadir}/selinux/devel/Makefile %{name}.pp
bzip2 -9 selinux/%{name}.pp
%endif

%install
mkdir -p %{buildroot}/etc/{frr,rc.d/init.d,sysconfig,logrotate.d,pam.d,default} \
         %{buildroot}/var/log/frr %{buildroot}%{_infodir} \
         %{buildroot}%{_unitdir}

mkdir -p -m 0755 %{buildroot}%{_libdir}/frr
mkdir -p %{buildroot}%{_tmpfilesdir}

%make_install

# Remove this file, as it is uninstalled and causes errors when building on RH9
rm -rf %{buildroot}/usr/share/info/dir

install -p -m 644 %{SOURCE1} %{buildroot}%{_tmpfilesdir}/%{name}.conf
install -p -m 644 tools/etc/frr/daemons %{buildroot}/etc/frr/daemons
install -p -m 644 tools/frr.service %{buildroot}%{_unitdir}/frr.service
install -p -m 755 tools/frrinit.sh %{buildroot}%{frr_libdir}/frr
install -p -m 755 tools/frrcommon.sh %{buildroot}%{frr_libdir}/frrcommon.sh
install -p -m 755 tools/watchfrr.sh %{buildroot}%{frr_libdir}/watchfrr.sh

install -p -m 644 redhat/frr.logrotate %{buildroot}/etc/logrotate.d/frr
install -p -m 644 redhat/frr.pam %{buildroot}/etc/pam.d/frr
install -d -m 775 %{buildroot}/run/frr

install -p -D -m 0644 %{SOURCE2} ${RPM_BUILD_ROOT}/%{_sysusersdir}/frr.conf

%if 0%{?with_selinux}
install -D -m 644 selinux/%{name}.pp.bz2 \
        %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
install -D -m 644 selinux/%{name}.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{name}.if
%endif

# Delete libtool archives
find %{buildroot} -type f -name "*.la" -delete -print

#Upstream does not maintain a stable API, these headers from -devel subpackage are no longer needed
rm %{buildroot}%{_libdir}/frr/*.so
rm -r %{buildroot}%{_includedir}/frr/

%pre
%sysusers_create_compat %{SOURCE2}
exit 0

%post
%systemd_post frr.service

if [ -f %{_infodir}/%{name}.inf* ]; then
    install-info %{_infodir}/frr.info %{_infodir}/dir || :
fi

# Create dummy files if they don't exist so basic functions can be used.
# Only create frr.conf when first installing, otherwise it can change
# the behavior of the package
if [ $1 -eq 1 ]; then
    if [ ! -e %{_sysconfdir}/frr/frr.conf ]; then
        echo "hostname `hostname`" > %{_sysconfdir}/frr/frr.conf
        chown frr:frr %{_sysconfdir}/frr/frr.conf
        chmod 640 %{_sysconfdir}/frr/frr.conf
    fi
fi

#still used by vtysh, this way no error is produced when using vtysh
if [ ! -e %{_sysconfdir}/frr/vtysh.conf ]; then
    touch %{_sysconfdir}/frr/vtysh.conf
    chmod 640 %{_sysconfdir}/frr/vtysh.conf
    chown frr:frrvty %{_sysconfdir}/frr/vtysh.conf
fi


%postun
%systemd_postun_with_restart frr.service

%preun
%systemd_preun frr.service

#only when removing frr
if [ $1 -eq 0 ]; then
	if [ -f %{_infodir}/%{name}.inf* ]; then
    	install-info --delete %{_infodir}/frr.info %{_infodir}/dir || :
	fi
fi

%if 0%{?with_selinux}
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}
#/var/tmp and /var/run need to be relabeled as well if FRR is running before upgrade
if [ $1 == 2 ]; then
    %{_sbindir}/restorecon -R /var/tmp/frr &> /dev/null
    %{_sbindir}/restorecon -R /var/run/frr &> /dev/null
fi

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{name}
    %selinux_relabel_post -s %{selinuxtype}
fi
%endif

%check
make check PYTHON=%{__python3}

%files
%defattr(-,root,root)
%license COPYING
%doc doc/mpls
%dir %attr(750,frr,frr) %{_sysconfdir}/frr
%dir %attr(755,frr,frr) /var/log/frr
%dir %attr(755,frr,frr) /run/frr
%{_infodir}/*info*
%{_mandir}/man*/*
%dir %{frr_libdir}/
%{frr_libdir}/*
%{_bindir}/*
%dir %{_libdir}/frr
%{_libdir}/frr/*.so.*
%dir %{_libdir}/frr/modules
%{_libdir}/frr/modules/*
%config(noreplace) %attr(644,root,root) /etc/logrotate.d/frr
%config(noreplace) %attr(644,frr,frr) /etc/frr/daemons
%config(noreplace) /etc/pam.d/frr
%{_unitdir}/*.service
%dir /usr/share/yang
/usr/share/yang/*.yang
%{_tmpfilesdir}/%{name}.conf
%{_sysusersdir}/frr.conf

%if 0%{?with_selinux}
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.*
%{_datadir}/selinux/devel/include/distributed/%{name}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{name}
%endif

%changelog
* Wed Sep 13 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-11
- Resolves: #2231001 - Incorrect handling of a error in parsing of an invalid section of a BGP update can de-peer a router

* Thu Aug 10 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-10
- Related: #2216912 - adding sys_admin to capabilities

* Tue Aug 08 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-9
- Resolves: #2215346 - frr policy does not allow the execution of /usr/sbin/ipsec

* Mon Aug 07 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-8
- Resolves: #2216912 - SELinux is preventing FRR-Zebra to access to network namespaces

* Wed Jun 07 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-7
- Resolves: #2168855 - BFD not working through VRF

* Tue May 23 2023 Michal Ruprich <mruprich@redhat.com> - 8.3.1-6
- Resolves: #2184870 - Reachable assertion in peek_for_as4_capability function
- Resolves: #2196795 - denial of service by crafting a BGP OPEN message with an option of type 0xff
- Resolves: #2196796 - denial of service by crafting a BGP OPEN message with an option of type 0xff
- Resolves: #2196794 - out-of-bounds read exists in the BGP daemon of FRRouting

* Mon Nov 28 2022 Michal Ruprich <mruprich@redhat.com> - 8.3.1-5
- Resolves: #2147522 - It is not possible to run FRR as a non-root user

* Thu Nov 24 2022 Michal Ruprich <mruprich@redhat.com> - 8.3.1-4
- Resolves: #2144500 - AVC error when reloading FRR with provided reload script

* Wed Oct 19 2022 Michal Ruprich <mruprich@redhat.com> - 8.3.1-3
- Related: #2129743 - Adding missing rules for vtysh and other daemons

* Mon Oct 17 2022 Michal Ruprich <mruprich@redhat.com> - 8.3.1-2
- Resolves: #2128738 - out-of-bounds read in the BGP daemon may lead to information disclosure or denial of service

* Thu Oct 13 2022 Michal Ruprich <mruprich@redhat.com> - 8.3.1-1
- Resolves: #2129731 - Rebase FRR to the latest version
- Resolves: #2129743 - Add targeted SELinux policy for FRR
- Resolves: #2127494 - BGP incorrectly withdraws routes on graceful restart capable routers 

* Tue Jun 14 2022 Michal Ruprich - 8.2.2-4
- Resolves: #2095404 - frr use systemd-sysusers

* Tue May 24 2022 Michal Ruprich <mruprich@redhat.com> - 8.2.2-3
- Resolves: #2081304 - Enhanced TMT testing for centos-stream

* Mon May 02 2022 Michal Ruprich <mruprich@redhat.com> - 8.2.2-2
- Resolves: #2069571 - the dynamic routing setup does not work any more

* Mon May 02 2022 Michal Ruprich <mruprich@redhat.com> - 8.2.2-1
- Resolves: #2069563 - Rebase frr to version 8.2.2

* Tue Nov 16 2021 Michal Ruprich <mruprich@redhat.com> - 8.0-5
- Resolves: #2023318 - Rebuilding for the new json-c library

* Wed Sep 01 2021 Michal Ruprich <mruprich@redhat.com> - 8.0-4
- Resolves: #1997603 - ospfd not running with ospf opaque-lsa option used

* Mon Aug 16 2021 Michal Ruprich <mruprich@redhat.com> - 8.0-3
- Related: #1990858 - Fixing prefix-list duplication check

* Thu Aug 12 2021 Michal Ruprich <mruprich@redhat.com> - 8.0-2
- Related: #1990858 - Frr needs higher version of libyang

* Tue Aug 10 2021 Michal Ruprich <mruprich@redhat.com> - 8.0-1
- Resolves: #1990858 - Possible rebase of frr to version 8.0

* Mon Aug 09 2021 Mohan Boddu <mboddu@redhat.com> - 7.5.1-7
- Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
  Related: rhbz#1991688

* Wed Jul 21 2021 Michal Ruprich <mruprich@redhat.com> - 7.5.1-6
- Resolves: #1983967 - ospfd crashes in route_node_delete with assertion fail

* Wed Jun 16 2021 Mohan Boddu <mboddu@redhat.com> - 7.5.1-5
- Rebuilt for RHEL 9 BETA for openssl 3.0
  Related: rhbz#1971065

* Fri Jun 04 2021 Michal Ruprich <mruprich@redhat.com> - 7.5.1-4
- Resolves: #1958155 - Upgrading frr unconditionally creates /etc/frr/frr.conf, breaking existing configuration

* Fri Apr 23 2021 Michal Ruprich <mruprich@redhat.com> - 7.5.1-3
- Resolves: #1939456 - /etc/frr permissions are bogus
- Resolves: #1951303 - FTBFS in CentOS Stream

* Thu Apr 15 2021 Mohan Boddu <mboddu@redhat.com> - 7.5.1-2
- Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

* Tue Mar 16 2021 Michal Ruprich <mruprich@redhat.com> - 7.5.1-1
- New version 7.5.1
- Enabling grpc, adding hostname for post scriptlet
- Moving files to libexec due to selinux issues

* Tue Feb 16 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-3
- Fixing FTBS - icc options are confusing the new gcc

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 7.5-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Fri Jan 01 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-1
- New version 7.5

* Mon Sep 21 2020 Michal Ruprich <mruprich@redhat.com> - 7.4-1
- New version 7.4

* Thu Aug 27 2020 Josef Řídký <jridky@redhat.com> - 7.3.1-4
- Rebuilt for new net-snmp release

* Mon Jul 27 2020 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Thu Jun 18 2020 Michal Ruprich <mruprich@redhat.com> - 7.3.1-1
- New version 7.3.1
- Fixes a couple of bugs(#1832259, #1835039, #1830815, #1830808, #1830806, #1830800, #1830798, #1814773)

* Tue May 19 2020 Michal Ruprich <mruprich@redhat.com> - 7.3-6
- Removing texi2html, it is not available in Rawhide anymore

* Mon May 18 2020 Michal Ruprich <mruprich@redhat.com> - 7.3-5
- Rebuild for new version of libyang

* Tue Apr 21 2020 Björn Esser <besser82@fedoraproject.org> - 7.3-4
- Rebuild (json-c)

* Mon Apr 13 2020 Björn Esser <besser82@fedoraproject.org> - 7.3-3
- Update json-c-0.14 patch with a solution from upstream

* Mon Apr 13 2020 Björn Esser <besser82@fedoraproject.org> - 7.3-2
- Add support for upcoming json-c 0.14.0

* Wed Feb 19 2020 Michal Ruprich <mruprich@redhat.com> - 7.3-1
- New version 7.3

* Tue Jan 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 7.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Mon Dec 16 2019 Michal Ruprich <mruprich@redhat.com> - 7.2-1
- New version 7.2

* Tue Nov 12 2019 Michal Ruprich <mruprich@redhat.com> - 7.1-5
- Rebuilding for new version of libyang

* Mon Oct 07 2019 Michal Ruprich <mruprich@redhat.com> - 7.1-4
- Adding noreplace to the /etc/frr/daemons file

* Fri Sep 13 2019 Michal Ruprich <mruprich@redhat.com> - 7.1-3
- New way of finding python version during build
- Replacing crypto of all routing daemons with openssl
- Disabling EIGRP crypto because it is broken
- Disabling crypto in FIPS mode

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 7.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Tue Jun 25 2019 Michal Ruprich <mruprich@redhat.com> - 7.1-1
- New version 7.1

* Wed Jun 19 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-2
- Initial build

