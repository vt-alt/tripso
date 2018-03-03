%define module_name     tripso
%define module_version  1.0
%define module_release  alt1
%define flavour         @kflavour@

BuildRequires(pre): rpm-build-kernel
BuildRequires(pre): kernel-headers-modules-@kflavour@

%setup_kernel_module %flavour

%define module_dir /lib/modules/%kversion-%flavour-%krelease/misc

Name: kernel-modules-%module_name-%flavour
Summary: Translate between CISPO and AstraLinux labels
License: GPLv2
Group: System/Kernel and hardware
Url: https://github.com/vt-alt/tripso/
Version: %module_version
Release: %module_release.%kcode.%kbuildrelease

ExclusiveOS: Linux
BuildRequires(pre): rpm-build-kernel
BuildRequires: kernel-headers-modules-%flavour = %kepoch%kversion-%krelease
BuildRequires: kernel-source-tripso

Provides: kernel-modules-%module_name-%kversion-%flavour-%krelease = %version-%release
Conflicts: kernel-modules-%module_name-%kversion-%flavour-%krelease < %version-%release
Conflicts: kernel-modules-%module_name-%kversion-%flavour-%krelease > %version-%release

PreReq: kernel-image-%flavour = %kepoch%kversion-%krelease
ExclusiveArch: %karch

%description
Translate between CISPO and AstraLinux labels (kernel module).

%prep
rm -rf %module_name-%module_version
tar -jxvf %kernel_src/kernel-source-%module_name-%module_version.tar.bz2
%setup -D -T -n %module_name-%module_version

%build
make -C %_usrsrc/linux-%kversion-%flavour-%krelease M=$(pwd) modules VERSION=%version-%release

%install
install -d %buildroot/%module_dir
install -m644 -D xt_TRIPSO.ko %buildroot/%module_dir/xt_TRIPSO.ko

%files
%module_dir

%changelog
* %(date "+%%a %%b %%d %%Y") %{?package_signer:%package_signer}%{!?package_signer:%packager} %version-%release
- Build for kernel-image-%flavour-%kversion-%krelease.
