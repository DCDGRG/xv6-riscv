#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// here externs are used to declare variables and functions
extern struct proc proc[NPROC];
extern struct spinlock wait_lock;
extern uint64 total_syscall_count;
extern struct spinlock syscall_count_lock;
int count_free_pages(void);

uint64
sys_sysinfo(void)
{
  int param;
  struct proc *p;
  int active_proc_count = 0;
  uint64 current_total_syscalls;

  // Get the integer argument
  argint(0, &param);

  switch(param) {
    case 0:
      active_proc_count = 0;
      // Loop through the process table
      for(p = proc; p < &proc[NPROC]; p++) {
        acquire(&p->lock);
        if(p->state != UNUSED) {
          active_proc_count++;
        }
        release(&p->lock);
      }
      return active_proc_count;

    case 1: // Total number of system calls so far
      acquire(&syscall_count_lock);
      current_total_syscalls = total_syscall_count;
      release(&syscall_count_lock);
      return current_total_syscalls;

    case 2: // Number of free memory pages
      return count_free_pages();

    default: // Invalid parameter
      return -1;
  }
}

struct pinfo {
  int ppid;
  int syscall_count;
  int page_usage;
};

uint64
sys_procinfo(void)
{
  uint64 user_pinfo_ptr; // User pointer to struct pinfo
  struct pinfo kp;       // Kernel copy of the struct
  struct proc *p = myproc();

  // Get the pointer argument (address in user space)
  argaddr(0, &user_pinfo_ptr);

  // Check if the user provided a NULL pointer
  if(user_pinfo_ptr == 0) {
      return -1;
  }

  // Get parent PID - requires wait_lock for safe access to p->parent
  acquire(&wait_lock);
  kp.ppid = p->parent->pid;
  release(&wait_lock);

  // Get per-process syscall count - requires p->lock
  acquire(&p->lock);
  kp.syscall_count = p->syscall_count;
  // Calculate page usage - sz requires p->lock
  kp.page_usage = PGROUNDUP(p->sz) / PGSIZE;
  release(&p->lock);


  // Copy the kernel struct to the user-space address
  if(copyout(p->pagetable, user_pinfo_ptr, (char *)&kp, sizeof(kp)) < 0) {
    return -1;
  }
  return 0;
}
  