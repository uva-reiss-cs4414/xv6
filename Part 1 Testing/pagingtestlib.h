#include "types.h"
#include "user.h"
#include "mmu.h"
#include "fcntl.h"

//#define DEBUG
#define MAYBE_UNUSED __attribute__((unused))
#define EXEC_TEST_PTE_VALUES 16
#define MAX_COW_FORKS 4
#define NUM_COW_REGIONS 1

// for test development: #define ALLOC_CHECK

static char *real_argv0;
static int want_args = 1;
void cleanup();

uint hextoi(const char *value) {
    const char *p;
    p = value;
    uint result = 0;
    /* skip any leading whitespace */
    while (p[0] == ' ') {
        p += 1;
    }
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
            result += 10 + *p - 'a';
        } else if (*p >= 'A' && *p <= 'F') {
            result += 10 + *p - 'A';
        } else {
            printf(2, "malformed hexadecimal number '%s'\n", value);
            return 0;
        }
        /* advance to next character */
        p += 1;
    }
    return result;
}

uint decorhextoi(const char *value) {
    if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        return hextoi(value);
    } else {
        return atoi(value);
    }
}

struct option {
    const char *name;
    const char *description;
    int *value;
    int boolean;
};

static
void getopt_usage(char *argv0, struct option *options) {
   if (0 == strcmp(argv0, "AS-INIT")) {
       printf(2, "Options:\n");
   } else {
       printf(2, "Usage: %s ... \n", argv0);
   }
   for (struct option *option = options; option->name; option += 1) {
       printf(2, "  -%s", option->name);
       if (option->boolean) {
           printf(2, "\n");
       } else {
           printf(2, "=NUMBER (default: 0x%x)\n", *option->value);
       }
       printf(2, "    %s\n", option->description);
   }
   printf(2, "NUMBER can be a base-10 number or a base-16 number prefixed with '0x'\n");
}


MAYBE_UNUSED
void dump_for(const char *reason, int pid) {
#define STARTDUMP ">> About to call dumppagetable() for "
#define ENDDUMP ">> Finished call to dumppagetable() for "
    printf(1, STARTDUMP "%s\n", reason);
    dumppagetable(pid);
    printf(1, ENDDUMP "%s\n", reason);
}

MAYBE_UNUSED
int strprefix(const char *prefix, const char *target) {
    while (*prefix == *target && *prefix != '\0' && *target != '\0') {
        prefix += 1;
        target += 1;
    }
    if (*prefix == '\0')
        return 1;
    else
        return 0;
}

MAYBE_UNUSED
static
void getopt(int argc, char **argv, struct option *options) {
    for (int i = 1; i < argc; i += 1) {
        const char *p = argv[i];
        if (*p == '-') {
            p += 1;
            if (*p == '-') {
                p += 1;
            }
            if (0 == strcmp("help", p)) {
                getopt_usage(argv[0], options);
                cleanup();
            }
            int found = 0;
            for (struct option *option = options; option->name; option += 1) {
                if (strprefix(option->name, p)) {
                    int option_len = strlen(option->name);
                    if (option->boolean) {
                        if (p[option_len] != '\0')
                            continue;
                        *option->value = 1;
                    } else {
                        if (p[option_len] != '=') {
                            printf(2, "expected '=' after '-%s'\n", option->name);
                            exit();
                        }
                        *option->value = decorhextoi(p + option_len + 1);
                    }
                    found = 1;
                    break;
                }
            }
            if (!found) {
                printf(2, "unrecognized option '-%s'\n", p);
                cleanup();
            }
        } else {
            printf(2, "unrecogonized argument '%s'\n", p);
            cleanup();
        }
    }
}

struct test_pipes {
    int to_child[2];
    int from_child[2];
};

struct test_pipes NO_PIPES = {
    .to_child = { -1, -1 },
    .from_child = { -1, -1 },
};

struct alloc_test_info {
    struct test_pipes pipes;
    int alloc_size;
    int write_start;
    int write_end;
    int read_start;
    int read_end;
    int use_sys_read;
    int fork_after_alloc;
    int dump;
    int skip_free_check;
    int skip_pte_check;
};

typedef enum {
    TR_SUCCESS = 0,
    TR_FAIL_UNKNOWN = -1,
    TR_FAIL_SYNC = 1,
    TR_FAIL_PTE = 2, 
    TR_FAIL_SBRK = 3,
    TR_FAIL_NONDEMAND = 4,
    TR_FAIL_NONZERO = 5,
    TR_FAIL_READBACK = 6,
    TR_FAIL_FORK = 7,
    TR_FAIL_NO_FREE = 8,
    TR_FAIL_PARAM = 9,
} TestResult;

MAYBE_UNUSED
int max(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

__attribute__((noreturn))
static void CRASH(const char *message) {
    printf(2, "%s\n", message);
    exit();
}

MAYBE_UNUSED
static
int _init_pipes(struct test_pipes *pipes) {
    // initialize fds to ensure that pipe()
    // doesn't trigger page fault in the kernel
    pipes->from_child[0] = -1;
    pipes->from_child[1] = -1;
    if (pipe(pipes->from_child) < 0)
        CRASH("error creating pipes");
    pipes->to_child[0] = -1;
    pipes->to_child[1] = -1;
    if (pipe(pipes->to_child) < 0)
        CRASH("error creating pipes");
    return 0;
}

static
void _pipe_sync_setup_parent(struct test_pipes *pipes) {
    close(pipes->from_child[1]);
    pipes->from_child[1] = -1;
    close(pipes->to_child[0]);
    pipes->to_child[0] = -1;
}

static
void _pipe_sync_setup_child(struct test_pipes *pipes) {
    close(pipes->from_child[0]);
    pipes->from_child[0] = -1;
    close(pipes->to_child[1]);
    pipes->to_child[1] = -1;
}

static
void _pipe_sync_cleanup(struct test_pipes *pipes) {
    if (pipes->from_child[0] != -1)
        close(pipes->from_child[0]);
    if (pipes->from_child[1] != -1)
        close(pipes->from_child[1]);
    if (pipes->to_child[0] != -1)
        close(pipes->to_child[0]);
    if (pipes->to_child[1] != -1)
        close(pipes->to_child[1]);
}

static
void _pipe_send_child(struct test_pipes *pipes, int *values, int value_count) {
    if (pipes->from_child[1] != -1) {
        write(pipes->from_child[1], &value_count, 4);
        write(pipes->from_child[1], values, 4 * value_count);
    }
}

static
void _pipe_recv_parent(struct test_pipes *pipes, int *values, int *value_count) {
    if (pipes->from_child[0] != -1) {
        int actual_value_count = 0;
        int result = read(pipes->from_child[0], &actual_value_count, 4);
        if (result != 4) CRASH("problem communicating with child process via pipe (recv_parent 1)");
        if (*value_count > actual_value_count) {
            CRASH("too many values being sent from child");
        }
        *value_count = actual_value_count;
        values[0] = 0; // write to ensure read() does not trigger copy-on-write
        int offset = 0;
        do {
            result = read(
                pipes->from_child[0],
                (char *) values + offset,
                actual_value_count * 4 - offset);
            if (result == -1) {
                CRASH("problem communicating with child process via pipe (recv_parent 2)");
            }
            offset += result;
        } while (offset != actual_value_count * 4);
    }
}

static
void _pipe_sync_child(struct test_pipes *pipes) {
    if (pipes->from_child[1] != -1) {
#ifdef DEBUG
        printf(2, "sync child %d\n", pipes->from_child[1]);
#endif
        write(pipes->from_child[1], "S", 1);
        char c = 'X';
        read(pipes->to_child[0], &c, 1);
        if (c != 'S') CRASH("problem communicating with parent process via pipe");
#ifdef DEBUG
        printf(2, "done sync child\n");
#endif
    }
}

static
int _pipe_assert_broken_parent(struct test_pipes *pipes) {
    char c = 'X';
    int result = read(pipes->from_child[0], &c, 1);
    return (result != 1);
}

static
int _pipe_sync_parent(struct test_pipes *pipes) {
    if (pipes->from_child[0] != -1) {
#ifdef DEBUG
        printf(2, "sync parent %d\n", pipes->from_child[0]);
        if (pipes->from_child[0] == 0)
            CRASH("test_pipes at corrupted?\n");
#endif
        char c = 'X';
        read(pipes->from_child[0], &c, 1);
        if (c != 'S') CRASH("problem communicating with child process via pipe");
        write(pipes->to_child[1], "S", 1);
#ifdef DEBUG
        printf(2, "done sync parent\n");
#endif
    }
    return 1;
}

typedef enum {
    MAYBE_ALLOCATED = 0,
    IS_ALLOCATED = 1,
    NOT_ALLOCATED = 2,
} AllocateFlag;

typedef enum {
    NOT_GUARD = 0,
    IS_GUARD = 1,
    IS_SHARED = 2,
    MAYBE_SHARED = 3,
    NOT_SHARED = 4,
} ProtFlag;

typedef enum {
    WITH_FREE_CHECK = 0,
    NO_FREE_CHECK = 1,
} FreeCheckFlag;

static
int _same_pte_range(int pid_one, int pid_two, int start_va, int end_va, char *explain) {
    for (int addr = start_va; addr < end_va; addr += PGSIZE) {
        uint pte_one = getpagetableentry(pid_one, addr);
        uint pte_two = getpagetableentry(pid_two, addr);
        if (PTE_ADDR(pte_one) != PTE_ADDR(pte_two)) {
            printf(2, "ERROR: virtual address 0x%x%s assigned to different physical addresses in pids %d and %d\n",
                addr, explain, pid_one, pid_two);
            return 0;
        }
    }
    return 1;
}

static
int _different_pte_range(int pid_one, int pid_two, int start_va, int end_va, char *explain) {
    for (int addr = start_va; addr < end_va; addr += PGSIZE) {
        uint pte_one = getpagetableentry(pid_one, addr);
        uint pte_two = getpagetableentry(pid_two, addr);
        if (PTE_ADDR(pte_one) == PTE_ADDR(pte_two)) {
            printf(2, "ERROR: virtual address 0x%x%s assigned same physical addresses in pids %d and %d\n",
                addr, explain, pid_one, pid_two);
            return 0;
        }
    }
    return 1;
}

static
int _sanity_check_range(int pid, int start_va, int end_va,
                        int allocate_flag, int prot_flag,
                        int free_check,
                        const char *explain) {
    for (int addr = start_va; addr < end_va; addr += PGSIZE) {
        uint pte = getpagetableentry(pid, addr);
#ifdef DEBUG
        printf(1, "DEBUG: pte at %x for pid %d: %x\n", addr, pid, pte);
#endif
        if (!(pte & PTE_P)) {
            if (allocate_flag == IS_ALLOCATED) {
                printf(2, "ERROR: pid %d, address 0x%x%s not allocated (expected allocated)\n"
                          "       (according to getpagetableentry())\n",
                       pid, addr, explain);
                return 0;
            }
        } else if (allocate_flag == NOT_ALLOCATED) {
            printf(2, "ERROR: pid %d, address 0x%x%s is allocated (expected not allocated)\n"
                      "       (according to getpagetableentry())\n",
                   pid, addr, explain);
            return 0;
        } else {
            if (isphysicalpagefree(PTE_ADDR(pte) >> PTXSHIFT)) {
                printf(2, "ERROR: pid %d address 0x%x%s allocated freed physical page 0x%x\n"
                          "       (according to pagetableentry() and isphysicalpagefree())\n",
                    pid, addr, explain, PTE_ADDR(pte) >> PTXSHIFT);
            }
            if (PTE_ADDR(pte) == 0) {
                printf(2, "ERROR: pid %d address 0x%x%s allocated invalid physical page 0\n"
                          "       (according to pagetableentry() and isphysicalpagefree())\n",
                    pid, addr, explain);
            }
            if (pte & PTE_U) {
                if (prot_flag == IS_GUARD) {
                    printf(2, "ERROR: pid %d, address 0x%x%s is user-accessible (expected not)\n"
                              "       (according to getpagetableentry())\n",
                       pid, addr, explain);
                    return 0;
                }
            } else {
                if (prot_flag != IS_GUARD) {
                    printf(2, "ERROR: pid %d, address 0x%x%s not user-accessible (expected to be)\n"
                              "       (according to getpagetableentry())\n",
                       pid, addr, explain);
                    return 0;
                }
            }
            if (pte & PTE_W) {
                if (prot_flag == IS_SHARED) {
                    printf(2, "ERROR: pid %d, address 0x%x%s is writable (expected not be)\n"
                              "       (according to getpagetableentry())\n",
                       pid, addr, explain);
                    return 0;
                }
            } else {
                if (prot_flag == NOT_SHARED) {
                    printf(2, "ERROR: pid %d, address 0x%x%s is not writable (expected to be)\n"
                              "       (according to getpagetableentry())\n",
                              pid, addr, explain);
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int _sanity_check_range_self(
        int start_va, int end_va, int allocate_flag, int guard_flag, int free_check,
        const char *explain) {
    return _sanity_check_range(getpid(), start_va, end_va, allocate_flag, guard_flag, free_check, explain);
}

extern uint _get_guard();
__asm__("\n\
.global _get_guard\n\
_get_guard:\n\
    movl $0xFFF, %eax\n\
    notl %eax\n\
    andl %esp, %eax\n\
    subl $0x1000, %eax\n\
    ret\n\
");

MAYBE_UNUSED static TestResult _sanity_check_self_nonheap(int free_check) {
    uint guard = _get_guard();
    if (!_sanity_check_range_self(0, guard, IS_ALLOCATED, NOT_GUARD, free_check, " (memory before guard page, before new allocation)")) {
        return TR_FAIL_PTE;
    }
    if (!_sanity_check_range_self(guard, guard + PGSIZE, IS_ALLOCATED, IS_GUARD, free_check, " (guard page)")) {
        return TR_FAIL_PTE;
    }
    return TR_SUCCESS;
}

MAYBE_UNUSED static TestResult _test_exec_child(char **argv) {
    struct test_pipes pipes = {
        .to_child = { 3, 4 },
        .from_child = { 5, 6 },
    };
    _pipe_sync_setup_child(&pipes);
    _pipe_sync_child(&pipes);
    int result = _sanity_check_self_nonheap(WITH_FREE_CHECK);
    if (result != TR_SUCCESS)
        return result;
    _pipe_sync_child(&pipes);
    int pte_values[EXEC_TEST_PTE_VALUES] = {0};
    for (int i = 0; i < EXEC_TEST_PTE_VALUES; ++i) {
        pte_values[i] = getpagetableentry(getpid(), i << PTXSHIFT);
    }
    _pipe_send_child(&pipes, pte_values, EXEC_TEST_PTE_VALUES);
    _pipe_sync_child(&pipes);
    return TR_SUCCESS;
}

#define SAVED_PPN_COUNT 2048

MAYBE_UNUSED
static int saved_ppns[SAVED_PPN_COUNT] = {0};
MAYBE_UNUSED
static int saved_ppn_index = 0;
#ifdef ALLOC_CHECK
static volatile int kalloc_index = 0;
#endif

static void clear_saved_ppns() {
    saved_ppn_index = 0;
    /* write all saved_ppns to prevent unexpected allocations later */
    for (int i = 0; i < SAVED_PPN_COUNT; i += 1) {
        saved_ppns[i] = 0;
    }
#ifdef ALLOC_CHECK
    kalloc_index = 0;
    kalloc_index = getkallocindex();
#endif
}

static int save_ppns(int pid, int start_address, int end_address, int allow_missing) {
    for (int i = start_address; i < end_address; i += PGSIZE) {
        uint pte = getpagetableentry(pid, i);
        if (pte & PTE_P) {
            if (saved_ppn_index >= SAVED_PPN_COUNT / 2 && ((start_address >> PTXSHIFT) & 0xF) != 0) {
                continue;
            }
            if (saved_ppn_index >= SAVED_PPN_COUNT) {
                continue;
            }
            saved_ppns[saved_ppn_index] = PTE_ADDR(pte) >> PTXSHIFT;
            if (saved_ppns[saved_ppn_index] == 0) {
                printf(2, "ERROR: invalid physical page 0 allocated for virtual page 0x%x\n",
                    i);
                return 0;
            }
            saved_ppn_index += 1;
        } else if (!allow_missing) {
            printf(2, "ERROR: expected pid %d to have address %x allocated,\n"
                      "       but getpagetableentry() returned non-present\n"
                      "       page table entry (%x)\n", pid, i, pte);
            return 0;
        }
    }
    return 1;
}

static int verify_ppns_freed(const char *descr) {
#ifdef ALLOC_CHECK
    if (kalloc_index != getkallocindex()) {
        printf(2, "ERROR: unexpected page allocation happened\n");
    }
#endif
    for (int i = 0; i < saved_ppn_index; i += 1) {
        if (!isphysicalpagefree(saved_ppns[i])) {
            printf(2, "ERROR: physical page 0x%x (%s) not freed\n",
                   saved_ppns[i], descr, i);
            return 0;
        }
    }
    return 1;
}


MAYBE_UNUSED static TestResult _test_exec_parent(struct test_pipes *pipes, int child_pid) {
    int result = TR_SUCCESS;
    _pipe_sync_setup_parent(pipes);
    _pipe_sync_parent(pipes);
    clear_saved_ppns();
    if (!save_ppns(child_pid, 0, 16 * PGSIZE, 1))
        goto early_exit_child;
    _pipe_sync_parent(pipes);
    int pte_values_from_child[EXEC_TEST_PTE_VALUES];
    int num_pte_values = EXEC_TEST_PTE_VALUES;
    _pipe_recv_parent(pipes, pte_values_from_child, &num_pte_values);
    for (int i = 0; i < num_pte_values; i += 1) {
        if (pte_values_from_child[i] != getpagetableentry(child_pid, i << PTXSHIFT)) {
            printf(2, "ERROR: result of getpagetableentry(%d, 0x%x) in pid %d disagreed with pid %d\n",
                child_pid, i << PTXSHIFT, getpid(), child_pid);
            result = TR_FAIL_PTE;
            goto early_exit_child;
        }
    }
    _pipe_sync_parent(pipes);
    wait();
    _pipe_sync_cleanup(pipes);
    if (!verify_ppns_freed("allocated to now-exited exec()'d process")) {
        return TR_FAIL_NO_FREE;
    }
    return result;
early_exit_child:
    _pipe_sync_cleanup(pipes);
    kill(child_pid);
    wait();
    return result;
}

MAYBE_UNUSED static TestResult _test_exec() {
    printf(1, 
           "Running exec test\n"
           "  exec()ing new process\n"
           "  checking that\n"
           "    page table entries reportd by getpagetableentry() seem to have correct flags\n"
           "    and are reported as freed from isphysicalpagefree() only after process exits\n"
           );
    struct test_pipes pipes;
    /* FIXME: pass fd numbers to child */
    _init_pipes(&pipes);
    int pid = fork();
    if (pid == -1) return TR_FAIL_FORK;
    if (pid == 0) {
        int to_child0 = dup(pipes.to_child[0]);
        int to_child1 = dup(pipes.to_child[1]);
        int from_child0 = dup(pipes.from_child[0]);
        int from_child1 = dup(pipes.from_child[1]);
        close(3);
        if (3 != dup(to_child0)) CRASH("could not assign fd 3");
        close(4);
        if (4 != dup(to_child1)) CRASH("could not assign fd 4");
        close(5);
        if (5 != dup(from_child0)) CRASH("could not assign fd 5");
        close(6);
        if (6 != dup(from_child1)) CRASH("could not assign fd 6");
        close(to_child0);
        close(to_child1);
        close(from_child0);
        close(from_child1);
        const char *args[] = {
            real_argv0,
            "__TEST_CHILD__",
            (char*) 0,
        };
        exec((char*) real_argv0, (char**) args);
        exit();
    } else {
        int result = _test_exec_parent(&pipes, pid);
        _pipe_sync_cleanup(&pipes);
        if (result == TR_SUCCESS) {
            printf(1, "Test successful.\n");
        } else {
            printf(1, "Test failed.\n");
        }
        return result;
    }
}

MAYBE_UNUSED static TestResult _test_allocation_child(struct alloc_test_info *info) {
    int result = TR_SUCCESS;
    _pipe_sync_child(&info->pipes);
    int free_check = info->skip_free_check ? NO_FREE_CHECK : WITH_FREE_CHECK;
#ifdef DEBUG
    printf(1, "pre-allocate checks\n");
#endif
    uint guard = _get_guard();
    if (!_sanity_check_range_self(0, guard, IS_ALLOCATED, NOT_GUARD, free_check, " (memory before guard page, before new allocation)")) {
        result = max(result, TR_FAIL_PTE);
    }
    if (!_sanity_check_range_self(guard, guard + PGSIZE, IS_ALLOCATED, IS_GUARD, free_check, " (guard page)")) {
        result = max(result, TR_FAIL_PTE);
    }
    if (!_sanity_check_range_self(guard + PGSIZE, guard + PGSIZE * 2, IS_ALLOCATED, NOT_GUARD, free_check, " (stack page)")) {
        result = max(result, TR_FAIL_PTE);
    }
    char *old_brk = sbrk(0);
    if (!info->skip_pte_check) {
        if (!_sanity_check_range_self(guard + PGSIZE, (uint) old_brk, MAYBE_ALLOCATED, NOT_GUARD, free_check, " (heap before new allocation)")) {
            result = max(result, TR_FAIL_PTE);
        }
    }
    _pipe_sync_child(&info->pipes);
    if (info->dump)
        dump_for("allocation-pre-allocate", getpid());
    sbrk(info->alloc_size);
#ifdef DEBUG
    printf(1, "sbrk\n");
#endif
    char *new_brk = sbrk(0);
    if (new_brk - old_brk < info->alloc_size) {
        printf(2, "ERROR: sbrk() allocated too little (requested 0x%x bytes; break changed by 0x%x bytes)\n", info->alloc_size, new_brk - old_brk);
        return TR_FAIL_SBRK; // FIXME: should this not stop test?
    }
    if (!info->skip_pte_check) {
        if (! _sanity_check_range_self(PGROUNDUP((uint) old_brk), (uint) new_brk, NOT_ALLOCATED, NOT_GUARD, free_check,
            " (new heap immediately after sbrk())")) {
            result = max(result, TR_FAIL_NONDEMAND);
        }
    }
    _pipe_sync_child(&info->pipes);
#ifdef DEBUG
    printf(2, "read\n");
#endif
    if (info->dump)
        dump_for("allocation-pre-access", getpid());
    int read_start = info->read_start; int read_end = info->read_end;
    for (int i = read_start; i < read_end; ++i) {
       if (old_brk[i] != 0) {
           printf(2, "ERROR: non-zero value read 0x%x bytes into 0x%x byte allocation\n",
                i, info->alloc_size);
       }
    }
    if (!info->skip_pte_check) {
        if (read_end > read_start) {
            if (! _sanity_check_range_self(
                PGROUNDDOWN((uint) old_brk + read_start), 
                PGROUNDUP((uint) old_brk + read_end - 1),
                IS_ALLOCATED, NOT_GUARD, free_check,
                " (read-from alocation after read of zeroes)")) {
                result = max(result, TR_FAIL_PTE);
            }
        }
        if (! _sanity_check_range_self(
            PGROUNDUP((uint) old_brk), 
            PGROUNDDOWN((uint) old_brk + read_start - 1), 
            NOT_ALLOCATED, NOT_GUARD, free_check,
            " (new allocation before read from pages)")) {
            result = max(result, TR_FAIL_PTE);
        }
        if (! _sanity_check_range_self(
            PGROUNDUP((uint) old_brk + read_end),
            PGROUNDUP((uint) new_brk),
            NOT_ALLOCATED, NOT_GUARD, free_check,
            " (new allocation after read from pages)")) {
            result = max(result, TR_FAIL_PTE);
        }
    }
    _pipe_sync_child(&info->pipes);
#ifdef DEBUG
    printf(2, "post-read\n");
#endif
    _pipe_sync_child(&info->pipes);
#ifdef DEBUG
    printf(2, "write\n");
#endif
    if (info->use_sys_read) {
        int fds[2];
        if (pipe(fds) < 0)
            CRASH("error creating pipes");
        for (int i = info->write_start; i < info->write_end; i += 1) {
            char tmp = ('Q' + i) % 128;
            if (write(fds[1], &tmp, 1) != 1)
                CRASH("error writing to pipe");
            if (read(fds[0], &old_brk[i], 1) != 1)
                CRASH("error reading from pipe");
        }
        close(fds[0]);
        close(fds[1]);
    } else {
        for (int i = info->write_start; i < info->write_end; i += 1) {
            old_brk[i] = ('Q' + i) % 128;
        }
    }
    for (int i = info->read_start; i < info->read_end; i += 1) {
        if (i >= info->write_start && i < info->write_end) {
            if (old_brk[i] != ('Q' + i) % 128) {
                printf(2, "ERROR: could not read back written value from "
                           "offset 0x%x in 0x%x byte allocation\n",
                       i, info->alloc_size);
                result = max(result, TR_FAIL_READBACK);
            }
        } else {
            if (old_brk[i] != 0) {
                printf(2, "ERROR: non-zero value read 0x%x bytes into 0x%x byte allocation"
                          "       (after writing to non-overlapping part of allocation)\n",
                       i, info->alloc_size);
                result = max(result, TR_FAIL_READBACK);
            }
        }
    }
    for (int i = info->write_start; i < info->write_end; i += 1) {
        if (old_brk[i] != ('Q' + i) % 128) {
            printf(2, "ERROR: could not read back written value from "
                       "offset 0x%x in 0x%x byte allocation\n",
                   i, info->alloc_size);
            result = max(result, TR_FAIL_READBACK);
        }
    }
    if (!info->skip_pte_check) {
        if (info->write_end > info->write_start) {
            if (! _sanity_check_range_self(
                PGROUNDUP((uint) old_brk + info->write_start),
                PGROUNDUP((uint) old_brk + info->write_end),
                IS_ALLOCATED, NOT_GUARD, free_check,
                " (new allocation after write to pages)")) {
                result = max(result, TR_FAIL_PTE);
            }
        }
    }
    if (info->dump)
        dump_for("allocation-post-access", getpid());
    _pipe_sync_child(&info->pipes);
    if (info->fork_after_alloc) {
        int pid = fork();
        if (pid == -1) {
            CRASH("error from fork()");
        } else if (pid == 0) {
            exit();
        } else {
            wait();
        }
    }
    _pipe_send_child(&info->pipes, &result, 1);
    return result;
}


MAYBE_UNUSED
int _test_allocation_parent(int child_pid, struct alloc_test_info *info) {
    uint orig_heap_end = (uint) sbrk(0);
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    /* pre-allocation scan */
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    /* sbrk() */
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    /* read */
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    /* wait */
    clear_saved_ppns();
    if (!info->skip_free_check) {
        save_ppns(child_pid, orig_heap_end + info->read_start, orig_heap_end + info->read_end, 0);
    }
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    /* write */
    if (!_pipe_sync_parent(&info->pipes)) return TR_FAIL_SYNC;
    if (!info->skip_free_check) {
        save_ppns(child_pid, orig_heap_end + info->write_start, orig_heap_end + info->write_end, 0);
    }
    /* wait */
    int result = TR_FAIL_SYNC;
    int count = 1;
    _pipe_recv_parent(&info->pipes, &result, &count);
    /* exit */
    wait();
    if (!info->skip_free_check) {
        if (!verify_ppns_freed("page that should have been allocated because of heap read/write in now-exited child process")) {
            return TR_FAIL_NO_FREE;
        }
    }
    if (!info->skip_pte_check) {
        result = max(
            result,
            _sanity_check_self_nonheap(info->skip_free_check ? NO_FREE_CHECK : WITH_FREE_CHECK)
        );
    } 
    return result;
}

int zero_if_negative(int x) {
    if (x < 0)
        return 0;
    else
        return x;
}

TestResult test_allocation(int fork_p, struct alloc_test_info *info) {
    if (info->skip_pte_check)
        info->skip_free_check = 1;
    if (info->write_end > info->alloc_size) {
        printf(1, "ERROR: write_end after end of allocation\n");
        return TR_FAIL_PARAM;
    }
    if (info->read_end > info->alloc_size) {
        printf(1, "ERROR: read_end after end of allocation\n");
        return TR_FAIL_PARAM;
    }
    if (info->read_start < 0 || info->write_start < 0) {
        printf(1, "ERROR: negative offset\n");
        return TR_FAIL_PARAM;
    }
    printf(1, "Testing allocating 0x%x bytes of memory%s\n",
          info->alloc_size, fork_p ? " in a child process" : "");
    if (!info->skip_pte_check) {
        printf(1, "  checking page table entry flags%s\n"
                  "  checking that heap pages aren't allocated before use\n",
               info->skip_free_check ? "" :
                   "\n  and checking non-heap physical pages seem non-free" 
                   "\n    (according to isphysicalpagefree())");
    }
    printf(1, "  reading 0x%x bytes from offsets 0x%x through 0x%x\n"
              "  writing 0x%x bytes from offsets 0x%x through 0x%x%s\n",
              zero_if_negative(info->read_end - info->read_start),
              info->read_start, info->read_end,
              zero_if_negative(info->write_end - info->write_start),
              info->write_start, info->write_end,
              info->use_sys_read ? " using read() calls" : ""
    );
    if (info->fork_after_alloc) {
        printf(1, "  forking a grandchild process to make sure fork()\n"
                  "    still works with partially unused heap\n");
    }
    if (fork_p && !info->skip_free_check) {
        printf(1, "  checking that sample of allocated pages are free after\n"
                  "     the child proesss exits\n"
                  "  checking that pages still allocated to parent seem non-free\n");
    }
    if (fork_p) {
        _init_pipes(&info->pipes);
        int child_pid = fork();
        if (child_pid == -1) {
            return TR_FAIL_FORK;
        } else if (child_pid == 0) {
            _test_allocation_child(info);
            exit();
        } else {
            int result = _test_allocation_parent(child_pid, info);
            _pipe_sync_cleanup(&info->pipes);
            if (result == TR_FAIL_SYNC) {
                kill(child_pid);
                wait();
            }
            if (result == TR_SUCCESS) {
                printf(1, "Test successful.\n");
            }
            return result;
        }
    } else {
        info->pipes = NO_PIPES;
        int result = _test_allocation_child(info);
        if (result == TR_SUCCESS) {
            printf(1, "Test successful.\n");
        }
        return result;
    } 
}

struct cow_test_info {
    struct test_pipes all_pipes[MAX_COW_FORKS];
    int num_forks;
    int pre_alloc_size;
    // FIXME: char parent_write_between_children[NUM_COW_REGIONS];
    char parent_write[NUM_COW_REGIONS];
    int parent_write_index;

    char child_write[NUM_COW_REGIONS][MAX_COW_FORKS];
    int starts[NUM_COW_REGIONS];
    int ends[NUM_COW_REGIONS];
    int use_sys_read_child;

    int skip_free_check;
    int skip_pte_check;

    int dump;
    int pre_fork_p;
};

static char _heap_test_value(int offset, int child_index) {
    int adjusted_offset = offset + (offset >> PTXSHIFT) + (offset >> PDXSHIFT);
    return ('Q' + adjusted_offset + child_index);
}

MAYBE_UNUSED
static __attribute__((noinline)) void dummy_call_to_use_stack() {
}

MAYBE_UNUSED
static TestResult _cow_test_child(struct cow_test_info *info, char *heap_base, int child_index) {
    struct test_pipes *pipes = &info->all_pipes[child_index];
    _pipe_sync_setup_child(pipes);
    // ensure no surprising stack allocations
    dummy_call_to_use_stack();
    _pipe_sync_child(pipes);
    for (int region = 0; region < NUM_COW_REGIONS; region += 1) {
        char do_write = info->child_write[region][child_index];
#ifdef DEBUG
        printf(2, "cow test child: region %d, waiting\n", region);
#endif
        _pipe_sync_child(pipes);
#ifdef DEBUG
        printf(2, "cow test child: region %d, write %d, range 0x%x-0x%x\n", region, do_write,
            info->starts[region], info->ends[region]);
#endif
        int dummy_pipe_fds[2];
        if (do_write && info->use_sys_read_child) {
            if (pipe(dummy_pipe_fds) < 0)
                CRASH("error creating pipes");
        }
        for (int j = info->starts[region]; j < info->ends[region]; j += 1) {
            if (heap_base[j] != _heap_test_value(j, -1)) {
                printf(2, "ERROR: wrong value read from child %d at offset 0x%x\n",
                          child_index, j);
                return TR_FAIL_READBACK;
            }
            if (do_write) {
                if (info->use_sys_read_child) {
                    char tmp = _heap_test_value(j, child_index);
                    if (write(dummy_pipe_fds[1], &tmp, 1) != 1)
                        CRASH("error writing to temporary pipe");
                    if (read(dummy_pipe_fds[0], &heap_base[j], 1) != 1)
                        CRASH("error reading from pipe onto COW region");
                } else {
                    heap_base[j] = _heap_test_value(j, child_index);
                }
            }
        }
        if (do_write && info->use_sys_read_child) {
            close(dummy_pipe_fds[0]);
            close(dummy_pipe_fds[1]);
        }
#ifdef DEBUG
        printf(2, "cow test child: done write\n");
#endif
        _pipe_sync_child(pipes);
        for (int j = info->starts[region]; j < info->ends[region]; j += 1) {
            char expect = _heap_test_value(j, do_write ? child_index : -1);
            if (heap_base[j] != expect) {
                printf(2, "ERROR: wrong value read from child %d at offset 0x%x\n",
                          child_index, j);
                return TR_FAIL_READBACK;
            }
        }
#ifdef DEBUG
        printf(2, "cow test child: done readbacks\n");
#endif
    }
    _pipe_sync_child(pipes);
    return TR_SUCCESS;
}

MAYBE_UNUSED
static TestResult _cow_test_parent(struct cow_test_info *info) {
    int pids[MAX_COW_FORKS] = {0};
    int result = TR_FAIL_UNKNOWN;
    int free_check = info->skip_free_check ? NO_FREE_CHECK : WITH_FREE_CHECK;
    clear_saved_ppns();
    char *heap_base = sbrk(info->pre_alloc_size);
    if (heap_base == (char*) -1)
        return TR_FAIL_SBRK;
    if (!info->skip_pte_check) {
        if (!_sanity_check_range_self(
                PGROUNDUP((uint) heap_base),
                (uint) heap_base + info->pre_alloc_size,
                NOT_ALLOCATED,
                NOT_SHARED,
                free_check,
                " (allocated, unused heap in parent)")) {
            result = TR_FAIL_PTE;
        }
    }
    /* FIXME: make entire loop conditional */
    for (int region = 0; region < NUM_COW_REGIONS; ++region) {
        for (int j = info->starts[region]; j < info->ends[region]; j += 1) {
            heap_base[j] = _heap_test_value(j, -1);
        }
    }
    if (!info->skip_pte_check) {
        for (int region = 0; region < NUM_COW_REGIONS; ++region) {
            if (info->starts[region] < info->ends[region]) {
                if (!_sanity_check_range_self(
                        PGROUNDDOWN((uint) heap_base + info->starts[region]),
                        PGROUNDUP((uint) heap_base + info->ends[region]),
                        IS_ALLOCATED,
                        NOT_SHARED,
                        free_check,
                        " (written-to heap pages before fork()ing)")) {
                    result = max(result, TR_FAIL_PTE);
                }
            }
        }
    }
    if (info->dump)
        dump_for("copy-on-write-parent-before", getpid());
    for (int i = 0; i < info->num_forks; ++i) {
#ifdef DEBUG
        printf(2, "DEBUG: About to fork for index %d of %d\n", i, info->num_forks);
#endif 
        _init_pipes(&info->all_pipes[i]);
        pids[i] = fork();
        if (pids[i] == -1) {
            _pipe_sync_cleanup(&info->all_pipes[i]);
            printf(2, "ERROR: fork() failed\n");
            result = max(result, TR_FAIL_FORK);
            goto cleanup_children;
        } else if (pids[i] == 0) {
            _pipe_sync_setup_child(&info->all_pipes[i]);
            _cow_test_child(info, heap_base, i);
            exit();
        }
        _pipe_sync_setup_parent(&info->all_pipes[i]);
    }
#ifdef DEBUG
    printf(2, "DEBUG: cow test: completing initial PTE checks\n");
#endif 
    if (info->dump && info->num_forks > 0)
        dump_for("copy-on-write-child-before-writes", pids[0]);
    for (int region = 0; region < NUM_COW_REGIONS; ++region) {
        if (info->starts[region] < info->ends[region]) {
            if (!info->skip_pte_check && !_sanity_check_range_self(
                    PGROUNDDOWN((uint) heap_base + info->starts[region]),
                    PGROUNDUP((uint) heap_base + info->ends[region]),
                    IS_ALLOCATED,
                    IS_SHARED,
                    free_check,
                    " (written-to heap pages in parent after fork()ing, before post-fork() writes)")) {
                result = TR_FAIL_PTE;
                goto cleanup_children;
            }
            for (int i = 0; i < info->num_forks; i += 1) {
                if (!info->skip_pte_check && !_sanity_check_range(
                        pids[i],
                        PGROUNDDOWN((uint) heap_base + info->starts[region]),
                        PGROUNDUP((uint) heap_base + info->ends[region]),
                        IS_ALLOCATED,
                        IS_SHARED,
                        free_check,
                        " (written-to heap pages in child after fork()ing, before post-fork() writes)")) {
                    result = TR_FAIL_PTE;
                    goto cleanup_children;
                }
                if (!info->skip_pte_check && !_same_pte_range(getpid(), pids[i],
                        PGROUNDDOWN((uint) heap_base + info->starts[region]),
                        PGROUNDUP((uint) heap_base + info->ends[region]),
                        " (written-to heap pages in child after fork()ing, before post-fork() writes)")) {
                    result = TR_FAIL_PTE;
                    goto cleanup_children;
                }
            }
        }
    }
#ifdef DEBUG
    printf(2, "DEBUG: cow test: before first sync\n");
#endif 
    for (int i = 0; i < info->num_forks; ++i) {
        if (!_pipe_sync_parent(&info->all_pipes[i])) {
            result = TR_FAIL_SYNC;
            goto cleanup_children;
        }
    }
#ifdef DEBUG
    printf(2, "DEBUG: cow test: past first sync\n");
#endif 
    for (int region = 0; region < NUM_COW_REGIONS; ++region) {
#ifdef DEBUG
        printf(2, "cow test parent: region %d\n", region);
#endif
        int have_written = 0;
        for (int i  = -1; i < info->num_forks; ++i) {
            if (i >= 0) {
                if (!_pipe_sync_parent(&info->all_pipes[i])) { /* start write */
                    result = TR_FAIL_SYNC;
                    goto cleanup_children;
                }
                if (!_pipe_sync_parent(&info->all_pipes[i])) { /* finish write */
                    result = TR_FAIL_SYNC;
                    goto cleanup_children;
                }
                if (info->child_write[region][i]) {
                    if (info->dump && i == 0) {
                        dump_for("copy-on-write-child-after-write", pids[i]);
                    }
                    if (!info->skip_free_check) {
                        save_ppns(pids[i],
                                  (uint) heap_base + info->starts[region],
                                  (uint) heap_base + info->ends[region],
                                  0);
                    }
                }
                if (!info->child_write[region][i] && !have_written) {
                    if (!info->skip_pte_check && !_same_pte_range(pids[i], getpid(),
                            (uint) heap_base + info->starts[region],
                            (uint) heap_base + info->ends[region],
                            " (written to heap region before parent and this child have written)"
                        )) {
                        result = TR_FAIL_PTE;
                        goto cleanup_children;
                    }
                } else {
                    if (!_different_pte_range(pids[i], getpid(),
                            (uint) heap_base + info->starts[region],
                            (uint) heap_base + info->ends[region],
                            " (written to heap region after either parent or child wrote)"
                        )) {
                        result = TR_FAIL_PTE;
                        goto cleanup_children;
                    }
                }
            }
            int do_write = (i == info->parent_write_index && info->parent_write[region]);
            for (int j = info->starts[region]; j < info->ends[region]; j += 1) {
                if (heap_base[j] != _heap_test_value(j, have_written ? -2 : -1)) {
                    printf(2, "ERROR: wrong value read from parent at offset 0x%x\n", j);
                    result = TR_FAIL_READBACK;
                    goto cleanup_children;
                }
                if (do_write) {
                    heap_base[j] = _heap_test_value(j, -2);
                }
            }
            if (do_write) {
                have_written = 1;
            }
        }
    }
    if (info->dump) {
        dump_for("copy-on-write-parent-after", getpid());
    }
#ifdef ALLOC_CHECK
    kalloc_index = 0;
    kalloc_index = getkallocindex();
    printf(2, "past reset kalloc_index\n");
#endif
#ifdef DEBUG
    printf(2, "cow test parent: cleanup\n");
#endif
    for (int i = 0; i <info->num_forks; ++i) {
        _pipe_sync_parent(&info->all_pipes[i]);
        _pipe_sync_cleanup(&info->all_pipes[i]);
        wait();
    }
    result = TR_SUCCESS;
    if (!info->skip_free_check) {
        if (!verify_ppns_freed("page that should have been a copy for a child process")) {
            result = TR_FAIL_NO_FREE;
        }
    }
    return result;
cleanup_children:
    for (int i = 0; i < info->num_forks; i += 1) {
        if (pids[i]) {
            _pipe_sync_cleanup(&info->all_pipes[i]);
            kill(pids[i]);
            pids[i] = -1;
            wait();
        }
    }
    return result;
}

MAYBE_UNUSED 
static TestResult test_cow(struct cow_test_info *info) {
    printf(1, "Running copy-on-write test%s:\n"
              "  allocating 0x%x bytes on heap\n"
              "  writing to bytes 0x%x through 0x%x of it\n"
              "  using fork() to start %d child processes\n"
              "  checking page table entry flags\n",
              info->pre_fork_p ? " (in child process)" : "",
              info->pre_alloc_size,
              info->starts[0], info->ends[0],
              info->num_forks);
    if (!info->skip_free_check)
        printf(1, "  checking that physical pages allocated seem not free\n"
                  "     (according to isphysicalpagefree())\n");
    if (info->parent_write_index == -1)
        printf(1, "  writing to byte range from parent process\n");
    for (int i = 0; i < info->num_forks; i += 1) {
        if (info->child_write[0][i]) {
            printf(1, "  writing to byte range from child process %d%s\n", i,
                      info->use_sys_read_child ? " using read() syscall": "");
        }
        if (info->parent_write[0] && info->parent_write_index == i) {
            printf(1, "  writing to byte range from parent process\n");
        }
    }
    printf(1, "  and checking that appropriate pages are shared/not shared\n");
    if (!info->skip_free_check)
        printf(1, "  and checking that pages in child which should not be shared are freed\n");
    int result = _cow_test_parent(info);
    if (result == TR_SUCCESS)
        printf(1, "Test successful.\n");
    return result;
}

MAYBE_UNUSED 
static TestResult test_cow_in_child(struct cow_test_info *info) {
    info->pre_fork_p = 1;
    struct test_pipes pipes;
    _init_pipes(&pipes);
    int pid = fork();
    if (pid == -1) {
        CRASH("error from fork()");
    } else if (pid == 0) {
        _pipe_sync_setup_child(&pipes);
        int result = test_cow(info);
        _pipe_send_child(&pipes, &result, 1);
        _pipe_sync_cleanup(&pipes);
        exit();
    } else {
        int count = 1;
        int result = TR_FAIL_UNKNOWN;
        _pipe_sync_setup_parent(&pipes);
        _pipe_recv_parent(&pipes, &result, &count);
        _pipe_sync_cleanup(&pipes);
        wait();
        return result;
    }
}

MAYBE_UNUSED
static TestResult test_oob(uint heap_offset, int fork_p, int write_p, int guard_p) {
    if (guard_p) {
        if (heap_offset >= 4096) {
            heap_offset = 4095;
        }
        printf(1,
            "Testing out of bounds access %s 0x%x bytes after beginning of guard page\n",
            write_p ? "writing" : "reading", heap_offset);
    } else {
      printf(1,
          "Testing out of bounds access %s 0x%x bytes after end of heap\n",
          write_p ? "writing" : "reading", heap_offset);
    }
    if (fork_p) {
        printf(1, "  doing access in child process\n");
    }
    struct test_pipes pipes = NO_PIPES;
    int pid = -1;
    int result = TR_FAIL_UNKNOWN;
    if (fork_p) {
        _init_pipes(&pipes);
        pid = fork();
        if (pid == -1) {
            CRASH("fork() failed");
        } else if (pid != 0) {
            _pipe_sync_setup_parent(&pipes);
            if (!_pipe_sync_parent(&pipes)) {
                result = TR_FAIL_SYNC;
            }
            if (!_pipe_assert_broken_parent(&pipes)) {
                result = TR_FAIL_UNKNOWN;
            } else {
                result = TR_SUCCESS;
            }
            _pipe_sync_cleanup(&pipes);
            wait();
            if (result == TR_SUCCESS) {
                printf(1, "Test successful.\n");
            } else {
                printf(1, "Test failed.\n");
            }
            return result;
        } else {
            _pipe_sync_setup_child(&pipes);
            _pipe_sync_child(&pipes);
        }
    }
    char *p;
    if (guard_p) {
      p = (char*) _get_guard() + heap_offset;
    } else {
      p = sbrk(0) + heap_offset;
    }
    if (write_p) {
        __asm__ volatile(
            "movb $42, %b0"
            :"=m"(*p) /* output */
            : /* input */
            :"memory" /* clobber */
        );
    } else {
        __asm__ volatile(
            "movb %0, %%al"
            : /* output */
            :"m"(*p) /* input */
            :"%eax" /* clobber */
        );
    }
    if (fork_p) {
        _pipe_sync_child(&pipes);
        _pipe_sync_cleanup(&pipes);
        exit();
    }
    if (result == TR_SUCCESS) {
        printf(1, "Test successful.\n");
    } else {
        printf(1, "Test failed.\n");
    }
    return result;
}

static char *new_args[20];
static char input_buffer[200];

MAYBE_UNUSED
void setup(int *pargc, char ***pargv) {
    if (pargc) {
        real_argv0 = (*pargv)[0];
    }
    if (pargc && *pargc > 1 && 0 == strcmp((*pargv)[1], "__TEST_CHILD__")) {
        _test_exec_child(*pargv);
        exit();
    }
    if (getpid() == 1) {
        mknod("console", 1, 1);
        open("console", O_RDWR);
        dup(0);
        dup(0);
        if (want_args && pargc != 0) {
            printf(1, "Enter arguments (-help for usage info): ");
            gets(input_buffer, sizeof input_buffer - 1);
            input_buffer[strlen(input_buffer) - 1] = '\0';
            char *p = input_buffer;
            new_args[0] = "AS-INIT";
            *pargc = 1;
            do {
                new_args[*pargc] = p;
                p = strchr(p, ' ');
                if (p) {
                    *p = '\0';
                    p += 1;
                    *pargc += 1;
                } else {
                    *pargc += 1;
                }
            } while (p != 0 && *pargc + 1 < sizeof(new_args)/sizeof(new_args[0]));
            new_args[*pargc] = 0;
            *pargv = new_args;
        }
    }
}

MAYBE_UNUSED
void cleanup() {
    if (getpid() == 1) {
        shutdown();
    } else {
        exit();
    }
}

MAYBE_UNUSED
int run_cow_test_from_args(int argc, char **argv) {
    struct cow_test_info info = {
        .pre_fork_p = 0,
        .num_forks = 1,
        .pre_alloc_size = 4096,
        .parent_write[0] = 1,
        .parent_write_index = -1,

        .starts[0] = 512,
        .ends[0] = 1024,
    };
    int pre_fork_p = 0;
    int parent_first = 0, parent_middle = 0, parent_last = 0, parent_never = 0;
    int no_child_write = 0, child_write_except = -1, child_write_only = -1;
    struct option options[] = {
        {
            .name = "forks",
            .value = &info.num_forks,
            .description = "number of child processes to fork()",
            .boolean = 0,
        },
        {
            .name = "size",
            .value = &info.pre_alloc_size,
            .description = "size to allocate (before forking, in bytes)",
            .boolean = 0,
        },
        {
            .name = "start",
            .value = &info.starts[0],
            .description = "offset of first byte to write in allocation",
            .boolean = 0,
        },
        {
            .name = "end",
            .value = &info.ends[0],
            .description = "offset one after last byte to write in allocation",
            .boolean = 0,
        },
        {
            .name = "parent-first",
            .value = &parent_first,
            .description = "make parent write first (default)",
            .boolean = 1,
        },
        {
            .name = "parent-last",
            .value = &parent_last,
            .description = "make parent write last",
            .boolean = 1,
        },
        {
            .name = "parent-middle",
            .value = &parent_middle,
            .description = "make parent write between first and second child",
            .boolean = 1,
        },
        {
            .name = "parent-never",
            .value = &parent_never,
            .description = "skip parent write",
            .boolean = 1,
        },
        {
            .name = "no-child-write",
            .value = &no_child_write,
            .description = "make children not write (default: children do write)",
            .boolean = 1,
        },
        {
            .name = "child-write-except",
            .value = &child_write_except,
            .description = "if non-negative, make all children write except the one with the specified 0-based index",
        },
        {
            .name = "child-write-only",
            .value = &child_write_only,
            .description = "if non-negative, make only the child with the specified 0-based index write",
        },
        {
            .name = "use-sys-read-child",
            .value = &info.use_sys_read_child,
            .description = "make children use read() system call for their writes to the heap",
            .boolean = 1,
        },
        {
            .name = "skip-pte-check",
            .value = &info.skip_pte_check,
            .boolean = 1,
            .description = "skip page table entry checks (speeds up test, but only checks that the heap appears to have correct values when used by process)"
        },
        {
            .name = "skip-free-check",
            .value = &info.skip_free_check,
            .boolean = 1,
            .description = "skip all calls to isphysicalpagefree() (speeds up test, but doesn't check if you free things)",
        },
        {
            .name = "dump",
            .value = &info.dump,
            .description = "call dumppagetable() occassionally to aid debugging",
            .boolean = 1,
        },
        {
            .name = "pre-fork",
            .value = &pre_fork_p,
            .description = "run entire test in a child process",
            .boolean = 1,
        },
        {   .name = (char*) 0  },
    };
    getopt(argc, argv, options);
    if (parent_first + parent_middle + parent_last + parent_never > 1) {
        printf(2, "ERROR: specify at most one of -parent-first, parent-last, -parent-middle, -parent-never\n");
    }
    if (parent_first) {
        info.parent_write_index = -1;
    } else if (parent_middle) {
        info.parent_write_index = 0;
    } else if (parent_last) {
        info.parent_write_index = info.num_forks - 1;
    } else if (parent_never) {
        info.parent_write[0] = 0;
    }
    if (no_child_write) {
        for (int i = 0; i < info.num_forks; i += 1) {
            info.child_write[0][i] = 0;
        }
    } else if (child_write_only != -1) {
        for (int i = 0; i < info.num_forks; i += 1) {
            if (i == child_write_only) {
                info.child_write[0][i] = 1;
            } else {
                info.child_write[0][i] = 0;
            }
        }
    } else if (child_write_except != -1) {
        for (int i = 0; i < info.num_forks; i += 1) {
            if (i != child_write_except) {
                info.child_write[0][i] = 1;
            } else {
                info.child_write[0][i] = 0;
            }
        }
    } else {
        for (int i = 0; i < info.num_forks; i += 1) {
            info.child_write[0][i] = 1;
        }
    }
    if (pre_fork_p) {
        info.pre_fork_p = 1;
        return test_cow_in_child(&info);
    } else {
        return test_cow(&info);
    }
}

MAYBE_UNUSED
int run_alloc_test_from_args(int argc, char **argv) {
    struct alloc_test_info info = {
        .alloc_size = 4096,
        .read_start = 128,
        .read_end = 256,
        .write_start = 512,
        .write_end = 768,
        .use_sys_read = 0,
        .fork_after_alloc = 0,
        .dump = 0,
        .skip_free_check = 0,
    };
    int fork_p = 0;
    struct option options[] = {
        {
            .name = "fork",
            .value = &fork_p,
            .boolean = 1,
            .description = "fork() as part of test (which allows checking for memory being freed)",
        },
        {
            .name = "size",
            .value = &info.alloc_size,
            .boolean = 0,
            .description = "size to allocate",
        },
        {
            .name = "read-start",
            .value = &info.read_start,
            .boolean = 0,
            .description = "offset of start of read in heap allocation",
        },
        {
            .name = "read-end",
            .value = &info.read_end,
            .boolean = 0,
            .description = "offset of end of read in heap allocation",
        },
        {
            .name = "write-start",
            .value = &info.write_start,
            .boolean = 0,
            .description = "offset of start of write in heap allocation",
        },
        {
            .name = "write-end",
            .value = &info.write_end,
            .boolean = 0,
            .description = "offset of end of write in heap allocation",
        },
        {
            .name = "use-sys-read",
            .value = &info.use_sys_read,
            .boolean = 1,
            .description = "use the read() syscall to write into allocated memory",
        },
        {
            .name = "fork-after-alloc",
            .value = &info.fork_after_alloc,
            .boolean = 1,
            .description = "fork() after making and partly using allocation (to make sure fork() handles unallocated holes)",
        },
        {
            .name = "skip-pte-check",
            .value = &info.skip_pte_check,
            .boolean = 1,
            .description = "skip page table entry checks (speeds up test, but only checks that the heap appears to have correct values when used by process)"
        },
        {
            .name = "skip-free-check",
            .value = &info.skip_free_check,
            .boolean = 1,
            .description = "skip all calls to isphysicalpagefree() (speeds up test, but doesn't check if you free things)",
        },
        {
            .name = "dump",
            .value = &info.dump,
            .boolean = 1,
            .description = "call dumppagetable() often to enable debugging",
        },
        {
            .name = (char*) 0,
        },
    };
    getopt(argc, argv, options);
    return test_allocation(fork_p, &info);
}

MAYBE_UNUSED
int run_oob_from_args(int argc, char **argv) {
    int no_fork_p = 0;
    int guard_p = 0;
    int write_p = 0;
    int heap_offset = 0x1000;
    struct option options[] = {
        {
            .name = "offset",
            .value = &heap_offset,
            .description = "offset from end of the heap/guard page to write to",
        },
        {
            .name = "write",
            .value = &write_p,
            .boolean = 1,
            .description = "write to out-of-bounds memory (default: read)",
        },
        {
            .name = "guard",
            .value = &guard_p,
            .boolean = 1,
            .description = "access offset from guard page (default: offset from end of heap)",
        },
        {
            .name = "no-fork",
            .value = &no_fork_p,
            .boolean = 1,
            .description = "do not fork in test (prevents automatic detection of successful results)",
        },
        {
            .name = (char*) 0,
        }
    };
    getopt(argc, argv, options);
    int fork_p = !no_fork_p;
    return test_oob(heap_offset, fork_p, write_p, guard_p);
}

MAYBE_UNUSED
int run_test_from_args(int argc, char **argv) {
    if (0 == strcmp(argv[0], "cow")) {
        return run_cow_test_from_args(argc, argv);
    } else if (0 == strcmp(argv[0], "alloc")) {
        return run_alloc_test_from_args(argc, argv);
    } else if (0 == strcmp(argv[0], "exec")) {
        if (argc > 1 && 0 == strcmp(argv[1], "-help")) {
            printf(2, "The exec test type takes no options.\n");
            return TR_SUCCESS;
        } else {
            return _test_exec(argv[0]);
        }
    } else if (0 == strcmp(argv[0], "oob")) {
        return run_oob_from_args(argc, argv);
    } else {
        printf(2, "Usage: %s TEST-TYPE OPTIONS\n",
            real_argv0 ? "" : real_argv0);
        printf(2, "  TEST-TYPE is one of:\n"
                  "    oob\n"
                  "      out-of-bounds access test\n"
                  "    exec\n"
                  "      test page table contents and\n"
                  "      freeing for newly exec'd child process\n"
                  "    alloc\n"
                  "      allocation on demand test\n"
                  "    cow\n"
                  "      copy-on-write test\n"
                  "  OPTIONS varies by test\n"
                  "    you can always supply no options for a default test\n"
                  "    use OPTIONS of '-help' for a list\n"
                  "    of a test type's options\n"
                );
        return -1;
    }
}
