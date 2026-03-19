#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

dl_deps()
{
	[ -d "$DEPS" ] || mkdir -p "$DEPS"
	(
	cd "$DEPS"
	exists_dir libnfnetlink-* ||
		curl -Lo - https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2 | tar -xj || exit 5
	exists_dir libmnl-* ||
		curl -Lo - https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 | tar -xj || exit 5
	exists_dir libnetfilter_queue-* ||
		curl -Lo - https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2 | tar -xj || exit 5
	exists_dir zlib-* ||
		curl -Lo - https://zlib.net/fossils/zlib-1.3.1.tar.gz | tar -xz || exit 5
	exists_dir luajit2-* ||
		curl -Lo - https://github.com/openresty/luajit2/archive/refs/tags/v${LUAJIT_RELEASE}.tar.gz | tar -xz || exit 5
	exists_dir lua-* ||
		curl -Lo - https://www.lua.org/ftp/lua-${LUA_RELEASE}.tar.gz | tar -xz || exit 5
	)
}

build_netlink()
{
	for i in libmnl libnfnetlink libnetfilter_queue ; do
		(
		cd $i-*
		[ -f "Makefile" ] && make clean
		CFLAGS="$OPTIMIZE $MINSIZE $CFLAGS" \
		LDFLAGS="$LDMINSIZE $LDFLAGS" \
		./configure --prefix= --host=$TARGET CC=$CC LD=$LD --enable-static --disable-shared --disable-dependency-tracking
		make install -j$nproc DESTDIR=$STAGING_DIR
		)
		sed -i "s|^prefix=.*|prefix=$STAGING_DIR|g" $STAGING_DIR/lib/pkgconfig/$i.pc
	done
}
build_zlib()
{
(
cd zlib-*
[ -f "Makefile" ] && make clean
CFLAGS="$OPTIMIZE $MINSIZE $CFLAGS" \
LDFLAGS="$LDMINSIZE $LDFLAGS" \
./configure --prefix= --static
make install -j$nproc DESTDIR=$STAGING_DIR
)
}
build_lua()
{
(
	cd lua-${LUA_RELEASE}
	make clean
	make CC="$CC" AR="$AR rc" CFLAGS="$OPTIMIZE $MINSIZE $CFLAGS" LDFLAGS="$LDMINSIZE $LDFLAGS" linux -j$nproc
	make install INSTALL_TOP="$STAGING_DIR" INSTALL_BIN="$STAGING_DIR/bin" INSTALL_INC="$STAGING_DIR/include/lua${LUA_VER}" INSTALL_LIB="$STAGING_DIR/lib"
)
}
build_luajit()
{
	local CFL="$CFLAGS"
	local SYSMALLOC=
(
	cd luajit2-*
	CFLAGS="-Os"
	make clean
	case $TARGET in
		aarch64*|mips64*)
			# sysmalloc can cause troubles without GC64. GC64 slows down by 10-15%. better not to use sysmalloc and leave lj_alloc.
			;;
		*)
			# save some exe size
			SYSMALLOC=-DLUAJIT_USE_SYSMALLOC
	esac
	make BUILDMODE=static XCFLAGS="$SYSMALLOC -DLUAJIT_DISABLE_FFI $CFLAGS_PIC" HOST_CC="$HOST_CC" CROSS= CC="$CC" TARGET_AR="$AR rcus" TARGET_STRIP=$STRIP TARGET_CFLAGS="$OPTIMIZE $MINSIZE $CFL" TARGET_LDFLAGS="$CPU $LDMINSIZE $LDFLAGS"
	make install PREFIX= DESTDIR="$STAGING_DIR"
)
}
build_luajit_for_target()
{
	target_has_luajit $1 && {
		case "$1" in
			*64*)
				HOST_CC="$HOSTCC"
				;;
			*)
				HOST_CC="$HOSTCC -m32"
				;;
		esac
			build_luajit
	}
}

check_prog curl tar gzip bzip2 sed make cc pkg-config
check_h_files
dl_deps
check_toolchains
ask_target

CFLAGS_BASE="$CFLAGS"
for t in $TGT; do
        CFLAGS="$CFLAGS_BASE"
	buildenv $t
	CFLAGS="$CFLAGS $CFLAGS_PIC"
	pushd "$DEPS"
	install_h_files
	build_netlink
	build_zlib
	build_lua
	build_luajit_for_target $t
	popd
	buildenv_clear
done
