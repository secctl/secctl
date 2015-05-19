set -x
gcc -O2 -Wall -Wextra -Woverflow -Wformat-security -Wtype-limits -Wpadded -Wpointer-arith -Wsign-compare -Wsign-conversion -funsigned-char -fstack-protector -Wstack-protector -fpie -static secctl.c -o secctl
