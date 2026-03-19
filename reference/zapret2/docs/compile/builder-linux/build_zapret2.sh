#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

ZDIR="zapret2"
ZBASE="$EXEDIR"
BRANCH=master
ZURL=https://github.com/bol-van/zapret2/archive/refs/heads/${BRANCH}.zip
ZBIN="$EXEDIR/binaries"

dl_zapret2()
{
	if [ -d "$ZBASE/$ZDIR" ]; then
		dir_is_not_empty "$ZBASE/$ZDIR" && {
			echo "zapret2 dir is not empty. if you want to redownload - delete it."
			return
		}
		rmdir "$ZBASE/$ZDIR"
	fi
	(
	cd "$ZBASE"
	curl -Lo /tmp/zapret2.zip "$ZURL"
	unzip /tmp/zapret2.zip
	rm /tmp/zapret2.zip
	mv zapret2-${BRANCH} $ZDIR
	)
}

check_prog curl unzip make
dl_zapret2
check_toolchains
ask_target

[ -d "$ZBIN" ] || mkdir -p "$ZBIN"

CFLAGS_BASE="$CFLAGS"
for t in $TGT; do
        CFLAGS="$CFLAGS_BASE"
	buildenv $t

	translate_target $t || {
		echo COULD NOT TRANSLATE TARGET $t TO BIN DIR
		continue
	}

	pushd $ZBASE/$ZDIR

	LUA_JIT=0
	LCFLAGS="-I${STAGING_DIR}/include/lua${LUA_VER}"
	LLIB="-L${STAGING_DIR}/lib -llua"
	target_has_luajit $t && {
		LUA_JIT=1
		LCFLAGS="-I${STAGING_DIR}/include/luajit-${LUAJIT_VER}"
		LLIB="-L${STAGING_DIR}/lib -lluajit-${LUAJIT_LUA_VER}"
	}

	make clean
	LUA_JIT=$LUA_JIT LUA_VER=$LUA_VER LUAJIT_LUA_VER=$LUAJIT_LUA_VER \
	OPTIMIZE=$OPTIMIZE \
	MINSIZE=$MINSIZE \
	CFLAGS="-static-libgcc -I$STAGING_DIR/include $CFLAGS" \
	LDFLAGS="-L$STAGING_DIR/lib $LDFLAGS" \
	make CFLAGS_PIC="$CFLAGS_PIC" LDFLAGS_PIE="$LDFLAGS_PIE" LUA_JIT=$LJIT LUA_CFLAGS="$LCFLAGS" LUA_LIB="$LLIB"

	[ -d "$ZBIN/$ZBINTARGET" ] || mkdir "$ZBIN/$ZBINTARGET"
	cp -f binaries/my/* "$ZBIN/$ZBINTARGET"

	popd

	buildenv_clear
done

