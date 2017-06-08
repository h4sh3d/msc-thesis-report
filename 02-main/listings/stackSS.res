           SAFE STACK                                   UNSAFE STACK
| <args>                       |               | <address of exec_string>     |
| <address of return>          |               | 0x0badf00d                   |
| <saved ebp>                  |               | 0xcafebabe                   |
                                               | <address of pop; pop; ret>   |
                                               | <address of add_sh>          |
                                               | 0xdeadbeef                   |
                                               | <address of pop; ret>        |
                                               | <address of add_bin>         |
                                               | 0x42424242                   |
                                               | 0x41414141 ...               |
                                               |   ... (2000 bytes of 'A's)   |
