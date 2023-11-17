#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  if (argc != 2) printf(1, "%d\n", "invalid command: provide a ppn");
  else printf(1, "%d \n", isphysicalpagefree(atoi(argv[1])));
  exit();
}