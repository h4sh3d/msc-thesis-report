root@5017cf36ad41:/shared/rop# make check
./checksec.sh --file build/safe-stack
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH

./checksec.sh --file build/stack-cookie
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH
