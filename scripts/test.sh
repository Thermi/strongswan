#!/bin/bash
# Build script for Travis CI
set -x

fix_msys2() {
        curl -O https://www2.futureware.at/~nickoe/msys2-mirror/msys/i686/msys2-keyring-r21.b39fb11-1-any.pkg.tar.xz | exit 1
        curl -O https://www2.futureware.at/~nickoe/msys2-mirror/msys/i686/msys2-keyring-r21.b39fb11-1-any.pkg.tar.xz.sig | exit 1
        pacman-key --verify msys2-keyring-r21.b39fb11-1-any.pkg.tar.xz.sig || exit 1
        pacman -U --noconfirm msys2-keyring-r21.b39fb11-1-any.pkg.tar.xz
        rm msys2-keyring-r21.b39fb11-1-any.pkg.tar.xz*
        pacman --noconfirm -Sydd pacman
}

build_botan()
{
	# same revision used in the build recipe of the testing environment
	BOTAN_REV=2.15.0
	BOTAN_DIR=$DEPS_BUILD_DIR/botan

	if test -d "$BOTAN_DIR"; then
		cd $BOTAN_DIR
	else
		echo "$ build_botan()"

		# if the leak detective is enabled we have to disable threading support
		# (used for std::async) as that causes invalid frees somehow, the
		# locking allocator causes a static leak via the first function that
		# references it (e.g. crypter or hasher), so we disable that too
		if test "$LEAK_DETECTIVE" = "yes"; then
			BOTAN_CONFIG="--without-os-features=threads
						  --disable-modules=locking_allocator"
		fi
		# disable some larger modules we don't need for the tests
		BOTAN_CONFIG="$BOTAN_CONFIG --disable-modules=pkcs11,tls,x509,xmss
					  --prefix=$DEPS_PREFIX"

		git clone https://github.com/randombit/botan.git $BOTAN_DIR &&
		cd $BOTAN_DIR &&
		git checkout -qf $BOTAN_REV &&
		python ./configure.py --amalgamation $BOTAN_CONFIG &&
		make -j4 libs >/dev/null
	fi

	ret=$?
	if [ $ret != 0 ]
	then
		exit $ret
	fi
	$sudo make install >/dev/null &&
	$sudo ldconfig || exit $?
	cd -
}

build_wolfssl()
{
	WOLFSSL_REV=v4.4.0-stable
	WOLFSSL_DIR=$DEPS_BUILD_DIR/wolfssl

	if test -d "$WOLFSSL_DIR"; then
		cd $WOLFSSL_DIR
	else
		echo "$ build_wolfssl()"

		WOLFSSL_CFLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_DES_ECB"
		WOLFSSL_CONFIG="--prefix=$DEPS_PREFIX
			--disable-crypttests --disable-examples
			--enable-keygen --enable-rsapss --enable-aesccm
			--enable-aesctr --enable-des3 --enable-camellia
			--enable-curve25519 --enable-ed25519
			--enable-curve448 --enable-ed448
			--enable-sha3 --enable-shake256"
		git clone https://github.com/wolfSSL/wolfssl.git $WOLFSSL_DIR &&
		cd $WOLFSSL_DIR &&
		git checkout -qf $WOLFSSL_REV &&
		./autogen.sh &&
		./configure C_EXTRA_FLAGS="$WOLFSSL_CFLAGS" $WOLFSSL_CONFIG &&
		make -j4 >/dev/null		
	fi
	
	ret=$?
	if [ $ret != 0 ]
	then
		exit $ret
	fi
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_tss2()
{
	TSS2_REV=2.4.1
	TSS2_PKG=tpm2-tss-$TSS2_REV
	TSS2_DIR=$DEPS_BUILD_DIR/$TSS2_PKG
	TSS2_SRC=https://github.com/tpm2-software/tpm2-tss/releases/download/$TSS2_REV/$TSS2_PKG.tar.gz

	if test -d "$TSS2_DIR"; then
		# install tss2
		cd "$TSS2_DIR"
	else
		echo "$ build_tss2()"

		curl -L $TSS2_SRC | tar xz -C $DEPS_BUILD_DIR &&
		cd $TSS2_DIR &&
		./configure --prefix=$DEPS_PREFIX --disable-doxygen-doc &&
		make -j4 >/dev/null
	fi

	ret=$?
	if [ $ret != 0 ]
	then
		exit $ret
	fi

	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

fix_timezone() {
	if test -e /etc/timezone ; then
		return 0
	fi
	if test -n "$TZ"; then
		echo "TZ var not set. Defaulting to UTC timezone." >&2
	fi
	: ${TZ:=UTC}
	echo "$TZ" > /etc/timezone
	dpkg-reconfigure -f noninteractive tzdata || true
}

install_deps() {
	# configure.ac checks against the easy_install file in $PATH, which is only provided by the PIP egg, not the Ubuntu package!
	: ${DEPS:=FOO}
	case "$TRAVIS_OS_NAME" in
	osx)
		brew update && \
		brew install ${DEPS}
		;;
	freebsd)
		pkg install -y automake autoconf libtool pkgconf && \
		pkg install -y bison flex gperf gettext ${DEPS}
		;;
	linux)
		$sudo apt-get update -qq && \
		$sudo apt-get install -qq bison flex gperf gettext ${DEPS}
		;;
	esac

    case "$APPVEYOR" in
    true)
        sudo apt-get install -qq bison flex gperf gettext pkg-config ${DEPS}
        ;;
    True)
        pacman --noconfirm -Sy bison flex gperf gettext mingw-w64-x86_64-gmp gmp ccache unzip
        ;;
    esac
}

appveyor_set_vars() {
    if test -n "$APPVEYOR"
    then
        case "$APPVEYOR" in
        True)
            declare -g TRAVIS_OS_NAME=windows
        ;;   
        *)
            # Ubuntu or unknown
            declare -g TRAVIS_OS_NAME=linux
        ;;
        esac
        declare -g TRAVIS_COMMIT="$APPVEYOR_REPO_COMMIT" \
                TRAVIS_BUILD_NUMBER="$APPVEYOR_BUILD_NUMBER"
    fi
}
: ${TRAVIS_BUILD_DIR=$PWD}
: ${DEPS_BUILD_DIR=$TRAVIS_BUILD_DIR/..}
: ${DEPS_PREFIX=/usr/local}

appveyor_set_vars

TARGET=check

declare -g DEPS="libgmp-dev ccache gettext libtool tzdata"

CFLAGS="-g -O2 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -Werror"

#True is Windows, true is Ubuntu
# no sudo on Windows
if test "$APPVEYOR" = "True"; then
    declare -g sudo=""
else
    declare -g sudo="sudo"
fi
export DEBIAN_FRONTEND=noninteractive

# Make sure the printf-builtin test on AppVeyor (Windows platform) runs the
# windows compatible path and not the Linux/Unix specific path
if test "$TEST" == "printf-builtin" -a "$APPVEYOR" == "True"
then
    TEST=win64
fi

case "$TEST" in
default)
	# should be the default, but lets make sure
	CONFIG="--with-printf-hooks=glibc"
	;;
openssl*)
	CONFIG="--disable-defaults --enable-pki --enable-openssl --enable-pem"
	export TESTS_PLUGINS="test-vectors pem openssl!"
	DEPS="$DEPS libssl-dev"
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-pki --enable-gcrypt --enable-pkcs1"
	export TESTS_PLUGINS="test-vectors pkcs1 gcrypt!"
	DEPS="$DEPS libgcrypt11-dev"
	;;
botan)
	CONFIG="--disable-defaults --enable-pki --enable-botan --enable-pem"
	export TESTS_PLUGINS="test-vectors pem botan!"

	if test "$1" = "deps"; then
		install_deps
		build_botan
	fi
	;;
wolfssl)
	CONFIG="--disable-defaults --enable-pki --enable-wolfssl --enable-pem"
	export TESTS_PLUGINS="test-vectors pem wolfssl!"
	# build with custom options to enable all the features the plugin supports
	if test "$1" = "deps"; then
		install_deps
		build_wolfssl
	fi
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	;;
all|coverage|sonarcloud)
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-padlock --disable-fuzzing
			--disable-osx-attr --disable-tkm --disable-uci
			--disable-unwind-backtraces
			--disable-svc --disable-dbghelp-backtraces --disable-socket-win
			--disable-kernel-wfp --disable-kernel-iph --disable-winhttp"
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	if test "$TRAVIS_CPU_ARCH" != "amd64"; then
		CONFIG="$CONFIG --disable-aesni --disable-rdrand"
	fi
	if test "$TEST" != "coverage"; then
		CONFIG="$CONFIG --disable-coverage"
	else
		# not actually required but configure checks for it
		DEPS="$DEPS lcov"
	fi
	# Botan requires GCC 5.0, so disable it on Ubuntu 16.04
	if test -n "$UBUNTU_XENIAL"; then
		CONFIG="$CONFIG --disable-botan"
	fi
	DEPS="$DEPS libcurl4-gnutls-dev libsoup2.4-dev libunbound-dev libldns-dev
		  libmariadbclient-dev libsqlite3-dev clearsilver-dev libfcgi-dev
		  libpcsclite-dev libpam0g-dev binutils-dev libnm-dev libgcrypt20-dev
		  libjson-c-dev iptables-dev python-pip libtspi-dev libsystemd-dev
		  libldap2-dev curl libssl-dev ruby systemd libtool autoconf automake
		  python-setuptools"
	PYDEPS="tox"
	if test "$1" = "deps"; then

		build_wolfssl
		build_tss2
	fi
	;;
win*)
        CONFIG="--disable-defaults --enable-svc --enable-ikev2
                        --enable-ikev1 --enable-static --enable-test-vectors --enable-nonce
                        --enable-constraints --enable-revocation --enable-pem --enable-pkcs1
                        --enable-pkcs8 --enable-x509 --enable-pubkey --enable-acert
                        --enable-eap-tnc --enable-eap-ttls --enable-eap-identity
                        --enable-updown --enable-ext-auth --enable-libipsec
                        --enable-tnccs-20 --enable-imc-attestation --enable-imv-attestation
                        --enable-imc-os --enable-imv-os --enable-tnc-imv --enable-tnc-imc
                        --enable-pki --enable-swanctl --enable-socket-win
                        --enable-kernel-iph --enable-kernel-wfp --enable-winhttp"
        if [[ "$TEST" == wintun* ]]; then
                CONFIG="$CONFIG --enable-wintun --enable-kernel-libipsec --enable-libipsec"

        fi
        # no make check for Windows binaries unless we run on a windows host
        #CCACHE=ccache
        if test "$APPVEYOR" != "True"; then
                TARGET=
        else
                CONFIG="$CONFIG --enable-openssl"
                CFLAGS="$CFLAGS -I/c/OpenSSL-$TEST/include"
                LDFLAGS="-L/c/OpenSSL-$TEST"
                export LDFLAGS
        fi
        CFLAGS="$CFLAGS -mno-ms-bitfields  -DNOCRYPT -DWIN32 -lwinpthread"
        DEPS="gcc-mingw-w64-base ccache"
        CONFIG="--host=x86_64-w64-mingw32 $CONFIG --enable-dbghelp-backtraces"
        DEPS="gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev $DEPS"
        #CC="$CCACHE x86_64-w64-mingw32-gcc"
        CC="x86_64-w64-mingw32-gcc"
	;;
android)
	DEPS="$DEPS openjdk-8-jdk"
	if test "$1" = "deps"; then
		git clone git://git.strongswan.org/android-ndk-boringssl.git -b ndk-static \
			src/frontends/android/app/src/main/jni/openssl
	fi
	TARGET=distdir
	;;
osx)
	# this causes a false positive in ip-packet.c since Xcode 8.3
	CFLAGS="$CFLAGS -Wno-address-of-packed-member"
	# use the same options as in the Homebrew Formula
	CONFIG="--disable-defaults --enable-charon --enable-cmd --enable-constraints
			--enable-curl --enable-eap-gtc --enable-eap-identity
			--enable-eap-md5 --enable-eap-mschapv2 --enable-ikev1 --enable-ikev2
			--enable-kernel-libipsec --enable-kernel-pfkey
			--enable-kernel-pfroute --enable-nonce --enable-openssl
			--enable-osx-attr --enable-pem --enable-pgp --enable-pkcs1
			--enable-pkcs8 --enable-pki --enable-pubkey --enable-revocation
			--enable-scepclient --enable-socket-default --enable-sshkey
			--enable-stroke --enable-swanctl --enable-unity --enable-updown
			--enable-x509 --enable-xauth-generic"
	DEPS="bison gettext openssl curl"
	BREW_PREFIX=$(brew --prefix)
	export PATH=$BREW_PREFIX/opt/bison/bin:$PATH
	export ACLOCAL_PATH=$BREW_PREFIX/opt/gettext/share/aclocal:$ACLOCAL_PATH
	for pkg in openssl curl
	do
		PKG_CONFIG_PATH=$BREW_PREFIX/opt/$pkg/lib/pkgconfig:$PKG_CONFIG_PATH
		CPPFLAGS="-I$BREW_PREFIX/opt/$pkg/include $CPPFLAGS"
		LDFLAGS="-L$BREW_PREFIX/opt/$pkg/lib $LDFLAGS"
	done
	export PKG_CONFIG_PATH
	export CPPFLAGS
	export LDFLAGS
	;;
freebsd)
	# use the options of the FreeBSD port (including options), except smp,
	# which requires a patch but is deprecated anyway, only using the builtin
	# printf hooks
	CONFIG="--enable-kernel-pfkey --enable-kernel-pfroute --disable-scripts
			--disable-kernel-netlink --enable-openssl --enable-eap-identity
			--enable-eap-md5 --enable-eap-tls --enable-eap-mschapv2
			--enable-eap-peap --enable-eap-ttls --enable-md4 --enable-blowfish
			--enable-addrblock --enable-whitelist --enable-cmd --enable-curl
			--enable-eap-aka --enable-eap-aka-3gpp2 --enable-eap-dynamic
			--enable-eap-radius --enable-eap-sim --enable-eap-sim-file
			--enable-gcm --enable-ipseckey --enable-kernel-libipsec
			--enable-load-tester --enable-ldap --enable-mediation
			--enable-mysql --enable-sqlite --enable-tpm	--enable-unbound
			--enable-unity --enable-xauth-eap --enable-xauth-pam
			--with-printf-hooks=builtin --enable-attr-sql --enable-sql"
	DEPS="gmp openldap-client libxml2 mysql80-client sqlite3 unbound ldns"
	export GPERF=/usr/local/bin/gperf
	export LEX=/usr/local/bin/flex
	;;
fuzzing)
	CFLAGS="$CFLAGS -DNO_CHECK_MEMWIPE"
	CONFIG="--enable-fuzzing --enable-static --disable-shared --disable-scripts
			--enable-imc-test --enable-tnccs-20"
	# don't run any of the unit tests
	export TESTS_RUNNERS=
	# prepare corpora
	if test -z "$1"; then
		if test -z "$FUZZING_CORPORA"; then
			git clone --depth 1 https://github.com/strongswan/fuzzing-corpora.git fuzzing-corpora
			export FUZZING_CORPORA=$TRAVIS_BUILD_DIR/fuzzing-corpora
		fi
		# these are about the same as those on OSS-Fuzz (except for the
		# symbolize options and strip_path_prefix)
		export ASAN_OPTIONS=redzone=16:handle_sigill=1:strict_string_check=1:\
			allocator_release_to_os_interval_ms=500:strict_memcmp=1:detect_container_overflow=1:\
			coverage=0:allocator_may_return_null=1:use_sigaltstack=1:detect_stack_use_after_return=1:\
			alloc_dealloc_mismatch=0:detect_leaks=1:print_scariness=1:max_uar_stack_size_log=16:\
			handle_abort=1:check_malloc_usable_size=0:quarantine_size_mb=10:detect_odr_violation=0:\
			symbolize=1:handle_segv=1:fast_unwind_on_fatal=0:external_symbolizer_path=/usr/bin/llvm-symbolizer-3.5
	fi
	;;
nm|nm-no-glib)
	DEPS="gnome-common libsecret-1-dev libgtk-3-dev libnm-dev libnma-dev"
	if test "$TEST" = "nm"; then
		DEPS="$DEPS libnm-glib-vpn-dev libnm-gtk-dev"
	else
		CONFIG="$CONFIG --without-libnm-glib"
	fi
	cd src/frontends/gnome
	# don't run ./configure with ./autogen.sh
	export NOCONFIGURE=1
	;;
dist)
	TARGET=distcheck
	;;
apidoc)
	DEPS="gettext doxygen libtool"
	CONFIG="--disable-defaults"
	TARGET=apidoc
	;;
lgtm)
	DEPS="jq"

	if test -z "$1"; then
		# fall back to the parent of the latest commit (on new branches we might
		# not have a range, also on duplicate branches)
		base="${TRAVIS_COMMIT}^"
		if test -n "$TRAVIS_COMMIT_RANGE"; then
			base="${TRAVIS_COMMIT_RANGE%...*}"
			# after rebases, the first commit ID in the range might not be valid
			git rev-parse -q --verify $base
			if [ $? != 0 ]; then
				# this will always compare against master, while the range
				# otherwise only contains "new" commits
				base=$(git merge-base origin/master ${TRAVIS_COMMIT})
			fi
		fi
		base=$(git rev-parse $base)
		project_id=1506185006272

		echo "Starting code review for $TRAVIS_COMMIT (base $base) on lgtm.com"
		git diff --binary $base > lgtm.patch || exit $?
		curl -s -X POST --data-binary @lgtm.patch \
			"https://lgtm.com/api/v1.0/codereviews/${project_id}?base=${base}&external-id=${TRAVIS_BUILD_NUMBER}" \
			-H 'Content-Type: application/octet-stream' \
			-H 'Accept: application/json' \
			-H "Authorization: Bearer ${LGTM_TOKEN}" > lgtm.res || exit $?
		lgtm_check_url=$(jq -r '."task-result-url"' lgtm.res)
		if [ -z "$lgtm_check_url" -o "$lgtm_check_url" = "null" ]; then
			cat lgtm.res
			exit 1
		fi
		lgtm_url=$(jq -r '."task-result"."results-url"' lgtm.res)
		echo "Progress and full results: ${lgtm_url}"

		echo -n "Waiting for completion: "
		lgtm_status=pending
		while [ "$lgtm_status" = "pending" ]; do
			sleep 15
			curl -s -X GET "${lgtm_check_url}" \
				-H 'Accept: application/json' \
				-H "Authorization: Bearer ${LGTM_TOKEN}" > lgtm.res
			if [ $? != 0 ]; then
				echo -n "-"
				continue
			fi
			echo -n "."
			lgtm_status=$(jq -r '.status' lgtm.res)
		done
		echo ""

		if [ "$lgtm_status" != "success" ]; then
			lgtm_message=$(jq -r '.["status-message"]' lgtm.res)
			echo "Code review failed: ${lgtm_message}"
			exit 1
		fi
		lgtm_new=$(jq -r '.languages[].new' lgtm.res | awk '{t+=$1} END {print t}')
		lgtm_fixed=$(jq -r '.languages[].fixed' lgtm.res | awk '{t+=$1} END {print t}')
		echo -n "Code review complete: "
		printf "%b\n" "\e[1;31m${lgtm_new}\e[0m new alerts, \e[1;32m${lgtm_fixed}\e[0m fixed"
		exit $lgtm_new
	fi
	;;
*)
	echo "$0: unknown test $TEST" >&2
	exit 1
	;;
esac

case "$1" in
deps)
	case "$TRAVIS_OS_NAME" in
	linux)
		$sudo apt-get update -qq && \
		$sudo apt-get install -qq bison flex gperf gettext $DEPS
		install_deps
		fix_timezone
		exit 0
		;;
	osx)
		brew update && \
		brew install $DEPS
		;;
	freebsd)
		pkg install -y automake autoconf libtool pkgconf && \
		pkg install -y bison flex gperf gettext $DEPS
		;;
        windows)
                fix_msys2
                install_deps
                ;;
	esac
	exit $?
	;;
pydeps)
	test -z "$PYDEPS" || pip -q install --user $PYDEPS
	exit $?
	;;
build-deps)
	exit
	;;
*)
	;;
esac

CONFIG="$CONFIG
	--disable-dependency-tracking
	--enable-silent-rules
	--enable-test-vectors
	--enable-monolithic=${MONOLITHIC-no}
	--enable-leak-detective=${LEAK_DETECTIVE-no}"

echo "$ ./autogen.sh"
./autogen.sh || true
automake --add-missing || true
./autogen.sh || exit $?
echo "$ CC=$CC CFLAGS=\"$CFLAGS\" ./configure $CONFIG"
CC="$CC" CFLAGS="$CFLAGS" ./configure $CONFIG || exit $?

case "$TEST" in
apidoc)
	#disable verbosity or -x output will be written to make.warnings
	set +x
	exec 2>make.warnings
	;;
*)
	;;
esac

echo "$ make $TARGET"
case "$TEST" in
*sonarcloud)
        export SONAR_SCANNER_VERSION=4.2.0.1873
        # This implicitely (based on .appveyor.yml) only runs on Windows platforms, so travis won't ever run this
        if [[ "$TEST" == win* ]]
        then
            export SONAR_SCANNER_HOME=$DEPS_BUILD_DIR/.sonar/sonar-scanner-$SONAR_SCANNER_VERSION-windows
            curl --create-dirs -sSLo $DEPS_BUILD_DIR/.sonar/sonar-scanner.zip \
https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/\sonar-scanner-cli-\
$SONAR_SCANNER_VERSION-windows.zip || exit $?
            unzip -o $DEPS_BUILD_DIR/.sonar/sonar-scanner.zip -d $DEPS_BUILD_DIR/.sonar/ || exit $?
            export PATH=$SONAR_SCANNER_HOME/bin:$PATH
            export SONAR_SCANNER_OPTS="-server"
            curl --create-dirs -sSLo $DEPS_BUILD_DIR/.sonar/build-wrapper-win-x86.zip \
                    https://sonarcloud.io/static/cpp/build-wrapper-win-x86.zip
            unzip -o $DEPS_BUILD_DIR/.sonar/build-wrapper-win-x86.zip -d $DEPS_BUILD_DIR/.sonar/
            export PATH=$DEPS_BUILD_DIR/.sonar/build-wrapper-win-x86:$PATH
            build-wrapper-win-x86-64.exe --out-dir bw-output make -j4 || exit $?
        else
            if test -n "$APPVEYOR"
            then
                export SONAR_SCANNER_HOME=$HOME/.sonar/sonar-scanner-$SONAR_SCANNER_VERSION-linux
                curl --create-dirs -sSLo $HOME/.sonar/sonar-scanner.zip \
                    https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/\
sonar-scanner-cli-$SONAR_SCANNER_VERSION-linux.zip || exit $?
                unzip -o $HOME/.sonar/sonar-scanner.zip -d $HOME/.sonar/ || exit $?
                export PATH=$SONAR_SCANNER_HOME/bin:$PATH
                export SONAR_SCANNER_OPTS="-server"

                curl --create-dirs -sSLo $HOME/.sonar/build-wrapper-linux-x86.zip \
                    https://sonarcloud.io/static/cpp/build-wrapper-linux-x86.zip
                unzip -o $HOME/.sonar/build-wrapper-linux-x86.zip -d $HOME/.sonar/
                export PATH=$HOME/.sonar/build-wrapper-linux-x86:$PATH
            fi
            # there is an issue with the platform detection that causes sonarqube to
            # fail on bionic with "ERROR: ld.so: object '...libinterceptor-${PLATFORM}.so'
            # from LD_PRELOAD cannot be preloaded (cannot open shared object file)"
            # https://jira.sonarsource.com/browse/CPP-2027
            BW_PATH=$(dirname $(which build-wrapper-linux-x86-64))
            cp $BW_PATH/libinterceptor-x86_64.so $BW_PATH/libinterceptor-haswell.so
            # without target, coverage is currently not supported anyway because
            # sonarqube only supports gcov, not lcov
            build-wrapper-linux-x86-64 --out-dir bw-output make -j4 || exit $?
        fi
	;;
*)
	make -j4 $TARGET || exit $?
	;;
esac

case "$TEST" in
apidoc)
	if test -s make.warnings; then
		cat make.warnings
		exit 1
	fi
	rm make.warnings
	;;
*sonarcloud)
           case "$TEST" in
            win*)
                sonar-scanner.bat -Dsonar.organization=contauro-ag \
                -Dsonar.projectKey=contauro-ag_strongswan \
                -Dsonar.projectVersion="$(git describe)+${TRAVIS_BUILD_NUMBER}" \
                -Dsonar.sources=. \
                -Dsonar.cfamily.threads=2 \
                -Dsonar.cfamily.cache.enabled=true \
                -Dsonar.host.url=https://sonarcloud.io \
                -Dsonar.cfamily.cache.path=$HOME/.sonar-cache \
                -Dsonar.cfamily.build-wrapper-output=bw-output \
                -Dsonar.branch.name=${APPVEYOR_REPO_BRANCH} \
                -Dsonar.login=${SONARCLOUD_LOGIN}
            ;;
            *)
                sonar-scanner -Dsonar.organization=contauro-ag \
                -Dsonar.projectKey=contauro-ag_strongswan \
                -Dsonar.projectVersion="$(git describe)+${TRAVIS_BUILD_NUMBER}" \
                -Dsonar.sources=. \
                -Dsonar.cfamily.threads=2 \
                -Dsonar.cfamily.cache.enabled=true \
                -Dsonar.host.url=https://sonarcloud.io \
                -Dsonar.cfamily.cache.path=$HOME/.sonar-cache \
                -Dsonar.cfamily.build-wrapper-output=bw-output \
                -Dsonar.branch.name=${APPVEYOR_REPO_BRANCH} \
                -Dsonar.login=${SONARCLOUD_LOGIN}
            ;;
            esac
	rm -r bw-output .scannerwork
	;;
android)
	rm -r strongswan-*
	cd src/frontends/android
	echo "$ ./gradlew build"
	NDK_CCACHE=ccache ./gradlew build
	;;
*)
	;;
esac

# ensure there are no unignored build artifacts (or other changes) in the Git repo
unclean="$(git status --porcelain)"
if test -n "$unclean"; then
	echo "Unignored build artifacts or other changes:"
	echo "$unclean"
	exit 1
fi
