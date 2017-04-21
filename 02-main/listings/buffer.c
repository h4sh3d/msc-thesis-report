#include <stdlib.h>

void func(char *param1)
{
  char local_buffer[100];
  strcpy(local_buffer, param1);
}

int main(int argc, char **argv)
{
  func(argv[1]);
  return 0;
}
