#!/bin/bash

KDIR=/lib/modules/$(uname -r)/build

TMP_DIR=$(mktemp -d)
cd $TMP_DIR

echo "obj-m += module.o" > $TMP_DIR/Makefile
touch module.c
make -pn -C $KDIR  M=$TMP_DIR modules > $TMP_DIR/make_output 2> /dev/null

if [ "$1" == "-I" ]; then
	cat $TMP_DIR/make_output | grep "module.o" | grep gcc | cut -d';' -f3 | sed 's/ /\n/g' | grep "\-I" | sed "s%-I.%$KDIR%g"
else
	cat $TMP_DIR/make_output | grep "module.o" | grep gcc | cut -d';' -f3 | sed 's/ /\n/g' | grep "\-D"
fi

rm -fr $TMP_DIR
