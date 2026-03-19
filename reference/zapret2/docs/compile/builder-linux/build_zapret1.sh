#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

ZDIR="zapret"
ZBASE="$EXEDIR"
BRANCH=master
ZURL=https://github.com/bol-van/zapret/archive/refs/heads/${BRANCH}.zip
ZBIN="$EXEDIR/binaries"

dl_zapret1()
{
	if [ -d "$ZBASE/$ZDIR" ]; then
		dir_is_not_empty "$ZBASE/$ZDIR" && {
			echo "zapret dir is not empty. if you want to redownload - delete it."
			return
		}
		rmdir "$ZBASE/$ZDIR"
	fi
	(
	cd "$ZBASE"
	curl -Lo /tmp/zapret.zip "$ZURL"
	unzip /tmp/zapret.zip
	rm /tmp/zapret.zip
	mv zapret-${BRANCH} $ZDIR
	)
}

check_prog curl unzip make
dl_zapret1
check_toolchains
ask_target

[ -d "$ZBIN" ] || mkdir -p "$ZBIN"

CFLAGS_BASE="$CFLAGS"
for t in $TGT; do
        CFLAGS="$CFLAGS_BASE $MINSIZE"
	buildenv $t

	translate_target $t || {
		echo COULD NOT TRANSLATE TARGET $t TO BIN DIR
		continue
	}

	pushd $ZBASE/$ZDIR

	make clean
	OPTIMIZE=$OPTIMIZE \
	CFLAGS="-static-libgcc -I$STAGING_DIR/include $CFLAGS $CFLAGS_PIC" \
	LDFLAGS="-L$STAGING_DIR/lib $LDMINSIZE $LDFLAGS_PIE $LDFLAGS" \
	make

	[ -d "$ZBIN/$ZBINTARGET" ] || mkdir "$ZBIN/$ZBINTARGET"
	cp -f binaries/my/* "$ZBIN/$ZBINTARGET"

	popd

	buildenv_clear
done

