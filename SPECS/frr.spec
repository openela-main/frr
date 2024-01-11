%global frrversion	7.5.1
%global frr_libdir /usr/libexec/frr

%global _hardened_build 1
%global selinuxtype targeted
%bcond_without selinux

Name: frr
Version: 7.5.1
Release: 13%{?checkout}%{?dist}
Summary: Routing daemon
License: GPLv2+
URL: http://www.frrouting.org
Source0: https://github.com/FRRouting/frr/releases/download/%{name}-%{frrversion}/%{name}-%{frrversion}.tar.gz
Source1: %{name}-tmpfiles.conf
Source2: frr.fc
Source3: frr.te
Source4: frr.if
BuildRequires: perl-generators
BuildRequires: gcc
BuildRequires: net-snmp-devel
BuildRequires: texinfo libcap-devel autoconf automake libtool patch groff
BuildRequires: readline readline-devel ncurses ncurses-devel
BuildRequires: git pam-devel c-ares-devel
BuildRequires: json-c-devel bison >= 2.7 flex perl-XML-LibXML
BuildRequires: python3-devel python3-sphinx python3-pytest
BuildRequires: systemd systemd-devel
BuildRequires: libyang-devel >= 1.0.184
Requires: net-snmp ncurses
Requires(post): systemd /sbin/install-info
Requires(preun): systemd /sbin/install-info
Requires(postun): systemd
Requires: iproute
Requires: initscripts

%if 0%{?with_selinux}
Requires: (%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})
%endif

Provides: routingdaemon = %{version}-%{release}
Obsoletes: frr-sysvinit quagga frr-contrib

Patch0000: 0000-remove-babeld-and-ldpd.patch
Patch0001: 0001-use-python3.patch
Patch0002: 0002-enable-openssl.patch
Patch0003: 0003-disable-eigrp-crypto.patch
Patch0004: 0004-fips-mode.patch
Patch0006: 0006-CVE-2020-12831.patch
Patch0007: 0007-frrinit.patch
Patch0008: 0008-designated-router.patch
Patch0009: 0009-routemap.patch
Patch0010: 0010-moving-executables.patch
Patch0011: 0011-reload-bfd-profile.patch
Patch0012: 0012-graceful-restart.patch
Patch0013: 0013-CVE-2022-37032.patch
Patch0014: 0014-bfd-profile-crash.patch
Patch0015: 0015-CVE-2023-38802.patch

%description
FRRouting is free software that manages TCP/IP based routing protocols. It takes
a multi-server and multi-threaded approach to resolve the current complexity
of the Internet.

FRRouting supports BGP4, OSPFv2, OSPFv3, ISIS, RIP, RIPng, PIM, NHRP, PBR, EIGRP and BFD.

FRRouting is a fork of Quagga.

%if 0%{?with_selinux}
%package selinux
Summary:       Selinux policy for FRR
BuildArch:     noarch
Requires:      selinux-policy-%{selinuxtype}
Requires(post):        selinux-policy-%{selinuxtype}
BuildRequires: selinux-policy-devel
%{?selinux_requires}

%description selinux
SELinux policy modules for FRR package

%endif

%prep
%autosetup -S git
#SELinux
mkdir selinux
cp -p %{SOURCE2} %{SOURCE3} %{SOURCE4} selinux

%build
autoreconf -ivf

%configure \
    --sbindir=%{frr_libdir} \
    --sysconfdir=%{_sysconfdir}/frr \
    --libdir=%{_libdir}/frr \
    --libexecdir=%{_libexecdir}/frr \
    --localstatedir=%{_localstatedir}/run/frr \
    --enable-snmp=agentx \
    --enable-multipath=64 \
    --enable-vtysh=yes \
    --enable-ospfclient=no \
    --enable-ospfapi=no \
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

#SELinux policy
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
install -p -m 644 %{_builddir}/%{name}-%{frrversion}/tools/etc/frr/daemons %{buildroot}/etc/frr/daemons
install -p -m 644 %{_builddir}/%{name}-%{frrversion}/tools/frr.service %{buildroot}%{_unitdir}/frr.service
install -p -m 755 %{_builddir}/%{name}-%{frrversion}/tools/frrinit.sh %{buildroot}%{frr_libdir}/frr
install -p -m 755 %{_builddir}/%{name}-%{frrversion}/tools/frrcommon.sh %{buildroot}%{frr_libdir}/frrcommon.sh
install -p -m 755 %{_builddir}/%{name}-%{frrversion}/tools/watchfrr.sh %{buildroot}%{frr_libdir}/watchfrr.sh

install -p -m 644 %{_builddir}/%{name}-%{frrversion}/redhat/frr.logrotate %{buildroot}/etc/logrotate.d/frr
install -p -m 644 %{_builddir}/%{name}-%{frrversion}/redhat/frr.pam %{buildroot}/etc/pam.d/frr
install -d -m 775 %{buildroot}/run/frr

%if 0%{?with_selinux}
install -D -m 644 selinux/%{name}.pp.bz2 \
       %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
install -D -m 644 selinux/%{name}.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{name}.if
%endif

rm %{buildroot}%{_libdir}/frr/*.la
rm %{buildroot}%{_libdir}/frr/modules/*.la

#Upstream does not maintain a stable API, these headers from -devel subpackage are no longer needed
rm %{buildroot}%{_libdir}/frr/*.so
rm -r %{buildroot}%{_includedir}/frr/

%pre
getent group fttvty >/dev/null 2>&1 || groupadd -r frrvty >/dev/null 2>&1 || :
getent group frr >/dev/null 2>&1 || groupadd -r frr >/dev/null 2>&1 || :
getent passwd frr >/dev/null 2>&1 || useradd -M -r -g frr -s /sbin/nologin \
 -c "FRRouting suite" -d %{_localstatedir}/run/frr frr || :
usermod -aG frrvty frr

%post
#Because we move files to /usr/libexec, we need to reload .service files as well
/usr/bin/systemctl daemon-reload
%systemd_post frr.service

if [ -f %{_infodir}/%{name}.inf* ]; then
    install-info %{_infodir}/frr.info %{_infodir}/dir || :
fi

# Create dummy files if they don't exist so basic functions can be used.
if [ ! -e %{_sysconfdir}/frr/zebra.conf ]; then
    echo "hostname `hostname`" > %{_sysconfdir}/frr/zebra.conf
    chown frr:frr %{_sysconfdir}/frr/zebra.conf
    chmod 640 %{_sysconfdir}/frr/zebra.conf
fi

if [ ! -e %{_sysconfdir}/frr/vtysh.conf ]; then
    echo 'no service integrated-vtysh-config' > %{_sysconfdir}/frr/vtysh.conf
    chmod 640 %{_sysconfdir}/frr/vtysh.conf
    chown frr:frrvty %{_sysconfdir}/frr/vtysh.conf
fi

#Making sure that the old format of config file still works
#Checking whether .rpmnew conf file is present - in that case I want to change the old config
if [ -e %{_sysconfdir}/frr/daemons.rpmnew ]; then
    sed -i s'/watchfrr_/#watchfrr_/g' %{_sysconfdir}/frr/daemons
    sed -i s'/zebra=/#zebra=/g' %{_sysconfdir}/frr/daemons
fi

%postun
%systemd_postun_with_restart frr.service

#only when removing the package
if [ $1 -ge 0 ]; then 
	if [ -f %{_infodir}/%{name}.inf* ]; then
    	install-info --delete %{_infodir}/frr.info %{_infodir}/dir || :
	fi
fi

%preun
%systemd_preun frr.service

#SELinux
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
%doc zebra/zebra.conf.sample
%doc isisd/isisd.conf.sample
%doc ripd/ripd.conf.sample
%doc bgpd/bgpd.conf.sample*
%doc ospfd/ospfd.conf.sample
%doc ospf6d/ospf6d.conf.sample
%doc ripngd/ripngd.conf.sample
%doc pimd/pimd.conf.sample
%doc doc/mpls
%dir %attr(740,frr,frr) %{_sysconfdir}/frr
%dir %attr(755,frr,frr) /var/log/frr
%dir %attr(755,frr,frr) /run/frr
%{_infodir}/*info*
%{_mandir}/man*/*
%dir %{frr_libdir}/
%{frr_libdir}/*
%{_bindir}/*
%dir %{_libdir}/frr
%{_libdir}/frr/*.so.*
%dir %{_libdir}/frr/modules/
%{_libdir}/frr/modules/*
%config(noreplace) %attr(644,root,root) /etc/logrotate.d/frr
%config(noreplace) %attr(644,frr,frr) /etc/frr/daemons
%config(noreplace) /etc/pam.d/frr
%{_unitdir}/*.service
%dir /usr/share/yang
/usr/share/yang/*.yang
%{_tmpfilesdir}/%{name}.conf

%if 0%{?with_selinux}
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.*
%{_datadir}/selinux/devel/include/distributed/%{name}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{name}
%endif

%changelog
* Wed Sep 13 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-13
- Resolves: #2231000 - Incorrect handling of a error in parsing of an invalid section of a BGP update can de-peer a router

* Wed Aug 23 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-12
- Resolves: #2216911 - Adding missing sys_admin SELinux call

* Mon Aug 21 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-11
- Related: #2216911 - Adding unconfined_t type to access namespaces

* Thu Aug 17 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-10
- Related: #2226803 - Adding patch

* Wed Aug 16 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-9
- Resolves: #2226803 - BFD crash in FRR running in MetalLB

* Fri Aug 11 2023 Michal Ruprich <mruprich@redhat.com> - 7.5.1-8
- Resolves: #2216911 - SELinux is preventing FRR-Zebra to access to network namespaces

* Wed Nov 30 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-7
- Resolves: #2128737 - out-of-bounds read in the BGP daemon may lead to information disclosure or denial of service

* Tue Nov 29 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-6
- Resolves: #1939516 - frr service cannot reload itself, due to executing in the wrong SELinux context

* Mon Nov 14 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-5
- Resolves: #2127140 - Frr is unable to push routes to the system routing table

* Mon Nov 14 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-4
- Resolves: #1948422 - BGP incorrectly withdraws routes on graceful restart capable routers

* Thu Aug 25 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-3
- Resolves: #2054160 - FRR reloader does not disable BFD when unsetting BFD profile

* Wed Aug 24 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-2
- Resolves: #1941765 - AVCs while running frr tests on RHEL 8.4.0 Beta-1.2
- Resolves: #1714984 - SELinux policy (daemons) changes required for package

* Wed May 11 2022 Michal Ruprich <mruprich@redhat.com> - 7.5.1-1
- Resolves: #2018451 - Rebase of frr to version 7.5.1
- Resolves: #1975361 - the dynamic routing setup does not work any more

* Wed Jan 05 2022 Michal Ruprich <mruprich@redhat.com> - 7.5-11
- Resolves: #2034328 - Bfdd crash in metallb CI

* Tue Jan 04 2022 Michal Ruprich <mruprich@redhat.com> - 7.5-10
- Resolves: #2020878 - frr ospfd show ip ospf interface does not show designated router info

* Fri Dec 10 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-9
- Resolves: #2029958 - FRR reloader generating invalid BFD configurations, exits with error

* Tue Nov 16 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-8
- Resolves: #2021819 - Rebuilding for the new json-c

* Thu Sep 30 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-7
- Related: #1917269 - Wrong value in gating file

* Fri Sep 17 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-6
- Related: #1917269 - Incomplete patch, adding gating rules

* Thu Sep 16 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-5
- Resolves: #1979426 - Unable to configure OSPF in multi-instance mode
- Resolves: #1917269 - vtysh running-config output not showing bgp ttl-security hops option

* Tue Jan 12 2021 root - 7.5-4
- Related: #1889323 - Fixing start-up with old config file

* Mon Jan 11 2021 root - 7.5-3
- Related: #1889323 - Reverting to non-integrated cofiguration

* Thu Jan 07 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-2
- Related: #1889323 - Obsoleting frr-contrib

* Thu Jan 07 2021 Michal Ruprich <mruprich@redhat.com> - 7.5-1
- Resolves: #1889323 - [RFE] Rebase FRR to 7.5

* Thu Aug 20 2020 Michal Ruprich <mruprich@redhat.com> - 7.0-10
- Resolves: #1867793 - FRR does not conform to the source port range specified in RFC5881

* Thu Aug 20 2020 Michal Ruprich <mruprich@redhat.com> - 7.0-9
- Resolves: #1852476 - default permission issue eases information leaks

* Tue May 05 2020 Michal Ruprich <mruprich@redhat.com> - 7.0-8
- Resolves: #1819319 - frr fails to start start if the initscripts package is missing

* Mon May 04 2020 Michal Ruprich <mruprich@redhat.com> - 7.0-7
- Resolves: #1758544 - IGMPv3 queries may lead to DoS

* Tue Mar 10 2020 Michal Ruprich <mruprich@redhat.com> - 7.0-6
- Resolves: #1776342 - frr has missing dependency on iproute

* Tue Sep 03 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-5
- Resolves: #1719465 - Removal of component Frr or its crypto

* Wed Jun 19 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-4
- Related: #1657029 - frr-contrib is back, it is breaking the rpmdeplint test

* Wed Jun 19 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-3
- Related: #1657029 - more cleanup, removed frr-contrib, frrvt changed to frrvty

* Wed Jun 19 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-2
- Related: #1657029 - cleaning specfile, adding Requires on libyang-devel

* Wed May 29 2019 Michal Ruprich <mruprich@redhat.com> - 7.0-1
- Resolves: #1657029 - Add FRR as a replacement of Quagga in RHEL 8
