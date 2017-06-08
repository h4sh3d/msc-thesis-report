root@5017cf36ad41:/shared/rop# ./exploit2.py
CANARY FOUND: 0x3cd25f00

root@5017cf36ad41:/shared/rop# ll
total 56K
-rw-r--r--  1 root root  886 Jun  8 17:39 Makefile
drwxr-xr-x  8 root root  272 Jun  8 17:33 build
-rwxr-xr-x  1 root root  27K May 21 14:21 checksec.sh
-rwxr-xr-x  1 root root  899 Jun  8 17:42 exploit2-ss.py
-rwxr-xr-x  1 root root 1.1K Jun  8 19:55 exploit2.py
-rw-r--r--  1 root root    8 Jun  8 19:55 hacked.txt       <<<<<<<<<<< GOT IT
-rw-r--r--  1 root root  664 Jun  8 18:22 rop2.c
