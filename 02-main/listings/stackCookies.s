mov    %gs:0x14,%ecx
mov    -0x4(%ebp),%edx
cmp    %edx,%ecx
mov    %eax,-0x38(%ebp)
jne    0x8048698 <vulnerable_function+152>
add    $0x48,%esp
pop    %ebp
ret
call   0x8048400 <__stack_chk_fail@plt>
