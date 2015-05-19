echo "###############################################################################"

tar cvvf - security/Kconfig\
	security/Kconfig.dist\
	security/Makefile\
	security/Makefile.dist\
	security/secctl/Kconfig\
	security/secctl/Makefile\
	security/secctl/*.c\
	security/secctl/*.h\
	security/secctl/*.sh\
	security/secctl/README\
	security/secctl/LICENSE\
	zzz.backup.sh\
	| gzip - > ../lsm-kernel-3.16.2-64-$$.tgz

set -x
ls -al ../lsm-kernel-3.16.2-64-$$.tgz
date
set -

echo "###############################################################################"
