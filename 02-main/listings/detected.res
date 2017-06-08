root@5017cf36ad41:/shared/rop# ./build/stack-cookie hello
hello
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: ./build/stack-cookie terminated
======= Backtrace: =========
/lib/i386-linux-gnu/i686/cmov/libc.so.6(+0x6c773)[0xf75d7773]
/lib/i386-linux-gnu/i686/cmov/libc.so.6(__fortify_fail+0x45)[0xf76679b5]
/lib/i386-linux-gnu/i686/cmov/libc.so.6(+0xfc96a)[0xf766796a]
./build/stack-cookie[0x804869d]
[0x41414141]
======= Memory map: ========
08048000-08049000 r-xp 00000000 00:29 21678309   /shared/rop/build/stack-cookie
08049000-0804a000 rw-p 00000000 00:29 21678309   /shared/rop/build/stack-cookie
08a45000-08a66000 rw-p 00000000 00:00 0          [heap]
f7546000-f7562000 r-xp 00000000 fe:01 1837482    /lib/i386-linux-gnu/libgcc_s.so.1
f7562000-f7563000 rw-p 0001b000 fe:01 1837482    /lib/i386-linux-gnu/libgcc_s.so.1
f756a000-f756b000 rw-p 00000000 00:00 0
f756b000-f7712000 r-xp 00000000 fe:01 1835752    /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
f7712000-f7714000 r--p 001a7000 fe:01 1835752    /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
f7714000-f7715000 rw-p 001a9000 fe:01 1835752    /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
f7715000-f7718000 rw-p 00000000 00:00 0
f771c000-f7721000 rw-p 00000000 00:00 0
f7721000-f7723000 r--p 00000000 00:00 0          [vvar]
f7723000-f7724000 r-xp 00000000 00:00 0          [vdso]
f7724000-f7743000 r-xp 00000000 fe:01 1835788    /lib/i386-linux-gnu/ld-2.19.so
f7743000-f7744000 r--p 0001f000 fe:01 1835788    /lib/i386-linux-gnu/ld-2.19.so
f7744000-f7745000 rw-p 00020000 fe:01 1835788    /lib/i386-linux-gnu/ld-2.19.so
ffa23000-ffa44000 rw-p 00000000 00:00 0          [stack]
Aborted
