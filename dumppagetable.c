#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  if (argc != 2) printf(1, "%s \n", "invalid command: provide a pid");
  else dumppagetable(atoi(argv[1]));
  exit();
}