#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  if (argc == 3) {
      printf(1, "%d \n", getpagetableentry());
  }
  else {
      printf(1, "%s\n", "invalid command: please provide 2 arguments");
  }
  exit();
}