#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct Number {
    int number;
    int (*operator)();
} Number;

int call(struct Number self)
{
    return self.operator(self.number);
}

int square(int number)
{
    return number * number;
}

int main(int argc, char **argv)
{
    int res;
    Number num_strcut;
    char buffer[20];

    num_strcut.operator = &square;
    num_strcut.number = 10;
    strcpy(buffer, argv[1]);

    res = call(num_strcut);
    printf("%i\n", res);

    return 0;
}
