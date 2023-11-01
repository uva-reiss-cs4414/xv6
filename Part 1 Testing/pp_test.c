#include "pagingtestlib.h"

int main(int argc, char **argv) {
    setup(&argc, &argv);
    run_test_from_args(argc - 1, argv + 1);
    cleanup();
}
