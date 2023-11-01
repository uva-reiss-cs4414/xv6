#include "types.h"
#include "user.h"
#include "mmu.h"

/* print out the contents of a page table entry (given as an integer) to stdout */
void dump_pte(pte_t pte) {
    if (pte & PTE_P) {
        printf(1, "P %s %s %x\n",
            pte & PTE_U ? "U" : "-",
            pte & PTE_W ? "W" : "-",
            PTE_ADDR(pte) >> PTXSHIFT
        );
    } else {
        printf(1, "- <not present>\n");
    }
}

void usage(const char *argv0) {
    printf(1,
        "%s: usage:\n"
        "   %s pte PID VA\n"
        "      show what getpagetableentry() entries for \n"
        "      the contents of the (last-level) page table\n"
        "      entry for pid PID (in decimal) and\n"
        "      virtual address VA (in hexadecimal)\n"
        "   %s dump PID\n"
        "      call dumppagetable(PID). PID is specified in decimal\n"
        "   %s isfree PPN\n"
        "      call isphysicalpagefree(PPN). PPN is specified in hexadecimal\n",
        argv0, argv0, argv0, argv0
    );
    exit();
}

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

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
    } else if (0 == strcmp(argv[1], "pte")) {
        if (argc != 4) { usage(argv[0]); }
        int pid = atoi(argv[2]);
        uint va = hextoi(argv[3]);
        uint raw_pte = getpagetableentry(pid, va);
        printf(1, "PID %d, last-level PTE for %x: ", pid, va);
        dump_pte(raw_pte);
        printf(1, "(raw value 0x%x)\n", raw_pte);
    } else if (0 == strcmp(argv[1], "dump")) {
        if (argc != 3) { usage(argv[0]); }
        int pid = atoi(argv[2]);
        dumppagetable(pid);
    } else if (0 == strcmp(argv[1], "isfree")) {
        if (argc != 3) { usage(argv[0]); }
        int ppn = hextoi(argv[2]);
        printf(1, "isphysicalpagefree(0x%x) = %d\n", ppn, isphysicalpagefree(ppn));
    } else {
        usage(argv[0]);
    }
    exit();
}
