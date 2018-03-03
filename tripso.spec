Name: tripso
Version: 1.0
Release: alt1

Summary: Translation of IPv4 Security Options (IPSO) Labels
License: GPLv2
Group: System/Kernel and hardware

Url: https://github.com/vt-alt/tripso
Source0: %name-%version.tar

BuildPreReq: rpm-build-kernel
BuildRequires: libiptables-devel

%description
Translate between CISPO and Astra Linux security labels (userspace part).

%package -n kernel-source-%name
Summary: Translate between CISPO and Astra Linux security labels (source)
Group: Development/Kernel
BuildArch: noarch
%description -n kernel-source-%name
Translate between CISPO and Astra Linux security labels (source).

%prep
%setup -q
tar -cjf ../%name-%version.tar.bz2 ../%name-%version

%build
make libxt_TRIPSO.so VERSION=%version

%install
make install-lib DESTDIR=%buildroot
mkdir -p %kernel_srcdir
install -pDm0644 ../%name-%version.tar.bz2 %kernel_srcdir/kernel-source-%name-%version.tar.bz2

%files -n kernel-source-%name
%attr(0644,root,root) %kernel_src/kernel-source-%name-%version.tar.bz2

%files
%doc README.md
/%_lib/iptables/*.so

%changelog
* Sat Mar 03 2018 Vitaly Chikunov <vt@altlinux.ru> 1.0-alt1
- Sisyphus package.
