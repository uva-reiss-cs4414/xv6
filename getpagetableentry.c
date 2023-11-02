#include "types.h"
#include "stat.h"
#include "user.h"

/* convert a hexadecimal number contained in the stirng 'value' to an uint */
uint hextoi(const char *value) {
    const char *p;
    p = value;
    uint result = 0;
    /* skip any leading 0x or 0X */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    while (*p) {
        /* shift previous values over 4 */
        result = result << 4;
        /* add next chraacter */
        if (*p >= '0' && *p <= '9') {
            result += *p - '0';
        } else if (*p >= 'a' && *p <= 'f') {
            result += (*p - 'a') + 10;
        } else if (*p >= 'A' && *p <= 'F') {
            result += (*p - 'A') + 10;
        } else {
            printf(2, "malformed hexadecimal number '%s'\n", value);
            return 0;
        }
        /* advance to next character */
        p += 1;
    }
    return result;
}

int
main(int argc, char *argv[])
{
  if (argc != 3) printf(1, "%s \n", "invalid command: provide pid and address");
  else {
    int pid = atoi(argv[1]);
    uint va = hextoi(argv[2]);
    printf(1, "%d\n", getpagetableentry(pid, va));
  }
  exit();
}