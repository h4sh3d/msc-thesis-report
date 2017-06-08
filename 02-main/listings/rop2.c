#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char string[100];

void exec_string() {
    system(string);
}

void add_bin(int magic) {
    if (magic == 0xdeadbeef) {
        strcat(string, "echo hacked!");
    }
}

void add_sh(int magic1, int magic2) {
    if (magic1 == 0xcafebabe && magic2 == 0x0badf00d) {
        strcat(string, "> hacked.txt");
    }
}

void vulnerable_function(char* fstring) {
    char buffer[20];
    printf(fstring);
    printf("\n");
    fflush(stdout);
    gets(buffer);
    printf("%s", buffer);
    fflush(stdout);
}

int main(int argc, char** argv) {
    string[0] = 0;
    vulnerable_function(argv[1]);
    return 0;
}
