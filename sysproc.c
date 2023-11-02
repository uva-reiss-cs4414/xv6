#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "vm.h"

int
sys_getpagetableentry(void)
{
  // return last-level page table entry for pid at virtual address
  // or 0 if there is no such page table entry
  int pid, address;
  if (argint(0, &pid) < 0 || argint(1, &address)) return -1;

  struct process_info info[NPROC];
  getprocessesinfohelper(info, NPROC);

  for (int i = 0; i < NPROC; i++) {
    if (info[i].pid == pid) { // find process with correct pid
        if (info[i].state == UNUSED) return -1;
        // retrieve page table entry for given address
        pde_t* pgdir = info[i].pgdir;
        pte_t* pgtab = walkpgdir(pgdir, (void*)address, 0);

        // check if page table entry exists
        if (pgtab == 0 || !(*pgtab & PTE_P)) {
            return 0;
        }

        int entry = *pgtab;
        return entry;
    }
  }

  return -1;
}

int
sys_isphysicalpagefree(void)
{
  // returns a true value if physical page number ppn is on the free list managed by kalloc.c
  // and a false value (0) otherwise.
  return 0;
}

int
sys_dumppagetable(void)
{
  // outputs the page table of the process with pid pid to the console
  int pid;
  if (argint(0, &pid) < 0) return -1;

  struct process_info info[NPROC];
  getprocessesinfohelper(info, NPROC);

  for (int i = 0; i < NPROC; i++) {
    if (info[i].pid == pid) { // find process with correct pid
      pde_t* pgdir = info[i].pgdir; 
      for (int pdx = 0; pdx < NPDENTRIES; pdx++) {
        // skip non-present page directory entries
        if (!(pgdir[pdx] & PTE_P)) continue;
        
        pde_t* pgtab = (pde_t*)P2V(PTE_ADDR(pgdir[pdx]));  // second-level page table

        // iterate through the second-level page table entries
        for (int ptx = 0; ptx < NPTENTRIES; ptx++) {
          pte_t pte = pgtab[ptx];

          // check if page is present
          if (pte & PTE_P) {
              cprintf("Virtual Page: %x, P: %d, U: %d, W: %d, Physical Page: %x\n",
                (pdx << PTXSHIFT) | ptx,  // calculate the virtual page number
                (pte & PTE_P) ? 1 : 0,    // check if the page is present
                (pte & PTE_U) ? 1 : 0,    // check user-mode accessibility
                (pte & PTE_W) ? 1 : 0,    // check writability
                PTE_ADDR(pte));           // extract physical page number
          } else {
              // non-present page
          }
        }
      } 
      break;
    }
  }
  return 0;
}

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

int
sys_yield(void)
{
  yield();
  return 0;
}

int sys_shutdown(void)
{
  shutdown();
  return 0;
}
