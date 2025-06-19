# SysGuard

gcc -fPIC -shared -o libblocker.so libblocker.c -lseccomp -ljson-c

gcc -o test_fork test_fork.c

python3 main.py
