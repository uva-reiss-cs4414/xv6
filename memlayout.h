// Memory layout

#define EXTMEM  0x100000            // Start of extended memory
#define PHYSTOP 0xE000000           // Top physical memory
#define DEVSPACE 0xFE000000         // Other devices are at high addresses

// Key addresses for address space layout (see kmap in vm.c for layout)
#define KERNBASE 0x80000000         // First kernel virtual address
#define KERNLINK (KERNBASE+EXTMEM)  // Address where kernel is linked

#ifndef __ASSEMBLER__

// Convert kernel virtual address to physical address
static inline uint V2P(void *a) {
    extern void panic(char*) __attribute__((noreturn));
    if (a < (void*) KERNBASE)
        panic("V2P on address < KERNBASE (not a kernel virtual address)");
    return (uint)a - KERNBASE;
}

// Convert physical address to kernel virtual address
static inline void *P2V(uint a) {
    extern void panic(char*) __attribute__((noreturn));
    if (a > KERNBASE)
        panic("P2V on address > KERNBASE");
    return (char*)a + KERNBASE;
}

#endif

// same as P2V, but suitable for a compile-time constant
#define P2V_C(x) (((char*) x) + KERNBASE)
// same as V2P, but suitable for a compile-time constant
#define V2P_C(x) (((uint) x) - KERNBASE)

#define V2P_WO(x) ((x) - KERNBASE)    // same as V2P, but without casts
#define P2V_WO(x) ((x) + KERNBASE)    // same as P2V, but without casts
