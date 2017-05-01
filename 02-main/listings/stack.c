#include <stdlib.h>

void func(int param1, int param2)
{
  int local1 = 8;
  char local_buffer[8] = "foobar";
}

int main(int argc, char **argv)
{
  func(512, 65536);
  return 0;
}
