all:
	gcc -fPIC -shared -o libblocker.so blocker.c -lseccomp -ljson-c
