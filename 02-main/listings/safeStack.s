push   %ebp
mov    %esp,%ebp
push   %esi
sub    $0x34,%esp
mov    0x8(%ebp),%eax
mov    0x806e26c,%ecx
mov    %gs:(%ecx),%edx
mov    %edx,%esi
add    $0xffffffe0,%esi
mov    %esi,%gs:(%ecx)
mov    %eax,-0x8(%ebp)
mov    -0x8(%ebp),%eax
mov    %esp,%esi
mov    %eax,(%esi)
mov    %edx,-0xc(%ebp)
mov    %ecx,-0x10(%ebp)
call   0x8048ea0 <printf@plt>
mov    %esp,%ecx
movl   $0x8060b56,(%ecx)
mov    %eax,-0x14(%ebp)
call   0x8048ea0 <printf@plt>
mov    0x8070c00,%ecx
mov    %esp,%edx
mov    %ecx,(%edx)
mov    %eax,-0x18(%ebp)
call   0x8048ec0 <fflush@plt>
mov    -0xc(%ebp),%ecx
add    $0xffffffec,%ecx
mov    %esp,%edx
mov    %ecx,(%edx)
mov    %eax,-0x1c(%ebp)
mov    %ecx,-0x20(%ebp)
call   0x8048ed0 <gets@plt>
mov    %esp,%ecx
mov    -0x20(%ebp),%edx
mov    %edx,0x4(%ecx)
movl   $0x8060b6f,(%ecx)
mov    %eax,-0x24(%ebp)
call   0x8048ea0 <printf@plt>
mov    0x8070c00,%ecx
mov    %esp,%edx
mov    %ecx,(%edx)
mov    %eax,-0x28(%ebp)
call   0x8048ec0 <fflush@plt>
mov    -0x10(%ebp),%ecx
mov    -0xc(%ebp),%edx
mov    %edx,%gs:(%ecx)
mov    %eax,-0x2c(%ebp)
add    $0x34,%esp
pop    %esi
pop    %ebp
ret
