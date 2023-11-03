#include "pagingtestlib.h"

static char *tests[][11] = {
    {
        "exec",
        (char*) 0,
    },
    {
        "oob",
        "-offset=0x1000",
        (char *) 0,
    },
    {
        "oob",
        "-offset=0x80000000",
        "-write",
        (char *) 0,
    },
    {
        "oob",
        "-guard",
        "-offset=0x800",
        (char *) 0,
    },
    {
        "oob",
        "-guard",
        "-offset=0x800",
        "-write",
        (char *) 0,
    },
    {
        "alloc",
        "-size=0x1000",
        "-read-start=0x40",
        "-read-end=0x100",
        "-write-start=0x0",
        "-write-end=0x0",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x2000",
        "-read-start=0x40",
        "-read-end=0x100",
        "-write-start=0x0",
        "-write-end=0x0",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x1000",
        "-read-start=0x40",
        "-read-end=0x100",
        "-write-start=0x0",
        "-write-end=0x0",
        "-fork-after-alloc",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x1000",
        "-read-start=0x0",
        "-read-end=0x0",
        "-write-start=0x40",
        "-write-end=0x100",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x3000",
        "-read-start=0x1040",
        "-read-end=0x1080",
        "-write-start=0x2010",
        "-write-end=0x2020",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x500000",
        "-read-start=0x402000",
        "-read-end=0x404000",
        "-write-start=0x404000",
        "-write-end=0x406000",
        "-fork",
        "-fork-after-alloc",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x50000000",
        "-read-start=0x0",
        "-read-end=0x0",
        "-write-start=0x40000000",
        "-write-end=0x49000000",
        "-skip-free-check",
        "-skip-pte-check",
        "-fork",
        (char*) 0,
    },
    {
        "alloc",
        "-size=0x1000",
        "-read-start=0x0",
        "-read-end=0x0",
        "-write-start=0x40",
        "-write-end=0x41",
        "-use-sys-read",
        (char*) 0,
    },
    {
        (char*) 0,
    }
};

void list_tests() {
    for (int i = 0; tests[i][0]; i += 1) {
        char **cur_test = tests[i];
        int cur_test_argc = 0;
        printf(1, "pp_test ");
        while (cur_test[cur_test_argc]) {
            printf(1, "%s ",cur_test[cur_test_argc]);
            cur_test_argc += 1;
        }
        printf(1, "\n");
    }
}

int
main(int argc, char **argv)
{
    if (argc > 1 && 0 == strcmp(argv[1], "-list")) {
        list_tests();
        exit();
    } else if (argc > 1 && 0 == strcmp(argv[1], "-help")) {
        printf(2, "Usage:\n"
                  "  %s\n"
                  "    Run test suite.\n"
                  "  %s -list\n"
                  "    List tests in test suite.\n"
                  "  %s -help\n"
                  "    This message.\n");
        exit();
    }
    want_args = 0;
    setup(&argc, &argv);
    int passed = 0, failed = 0;
    for (int i = 0; tests[i][0]; i += 1) {
        char **cur_test = tests[i];
        int cur_test_argc = 0;
        while (cur_test[cur_test_argc]) cur_test_argc += 1;
        if (run_test_from_args(cur_test_argc, cur_test) == TR_SUCCESS) {
            passed += 1;
        } else {
            printf(1, "*** TEST FAILURE ***\n");
            failed += 1;
        }
    }
    if (failed == 0) {
        printf(1, "All tests passed.\n");
    } else {
        printf(1, "Not all tests passed.\n");
    }
    cleanup();
}
