/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>

#define MYMODNAME "FindOffsets "

static int my_init_module(
    void);
static void my_cleanup_module(
    void);

static int
my_init_module(
    void)
{
    struct task_struct *p = NULL;
		struct mm_struct *mm = NULL;
		struct vm_area_struct *va = NULL;
		struct file *f = NULL;
		struct path *pa = NULL;
		struct dentry *d = NULL;
		// original task_struct offsets
    unsigned long commOffset;
    unsigned long tasksOffset;
    unsigned long mmOffset;
    unsigned long pidOffset;
    unsigned long pgdOffset;
    unsigned long addrOffset;
		// new offsets for walking the memory map
		unsigned long mmapOffset;
		unsigned long vaNextOffset;
		unsigned long vaStartOffset;
		unsigned long vaFileOffset;
		unsigned long pathOffset;
		unsigned long dentryOffset;
		unsigned long inameOffset;

    printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);
    p = current; // load whatever task_stuct is currently running, we don't care which

    if (p != NULL) {
        commOffset = (unsigned long) (&(p->comm)) - (unsigned long) (p);
        tasksOffset =
            (unsigned long) (&(p->tasks)) - (unsigned long) (p);
        mmOffset = (unsigned long) (&(p->mm)) - (unsigned long) (p);
        pidOffset = (unsigned long) (&(p->pid)) - (unsigned long) (p);
        pgdOffset =
            (unsigned long) (&(p->mm->pgd)) - (unsigned long) (p->mm);
        addrOffset =
            (unsigned long) (&(p->mm->start_code)) -
            (unsigned long) (p->mm);

        printk(KERN_ALERT "[domain name] {\n");
        printk(KERN_ALERT "    ostype = \"Linux\";\n");
        printk(KERN_ALERT "    sysmap = \"[insert path here]\";\n");
        printk(KERN_ALERT "    linux_name = 0x%x;\n",
               (unsigned int) commOffset);
        printk(KERN_ALERT "    linux_tasks = 0x%x;\n",
               (unsigned int) tasksOffset);
        printk(KERN_ALERT "    linux_mm = 0x%x;\n",
               (unsigned int) mmOffset);
        printk(KERN_ALERT "    linux_pid = 0x%x;\n",
               (unsigned int) pidOffset);
        printk(KERN_ALERT "    linux_pgd = 0x%x;\n",
               (unsigned int) pgdOffset);

				mm = p->mm; // find offsets in mm (mm_struct)
				mmapOffset = (unsigned long) (&(mm->mmap)) - (unsigned long) (mm);
        printk(KERN_ALERT "    linux_mmap = 0x%x;\n", (unsigned int) mmapOffset);

				va = mm->mmap; // find offsets in va (vm_area_struct)
				vaNextOffset = (unsigned long) (&(va->vm_next)) - (unsigned long) (va);
				vaStartOffset = (unsigned long) (&(va->vm_start)) - (unsigned long) (va);
				vaFileOffset = (unsigned long) (&(va->vm_file)) - (unsigned long) (va);
        printk(KERN_ALERT "    linux_vm_next = 0x%x;\n", (unsigned int) vaNextOffset);
        printk(KERN_ALERT "    linux_vm_start = 0x%x;\n", (unsigned int) vaStartOffset);
        printk(KERN_ALERT "    linux_vm_file = 0x%x;\n", (unsigned int) vaFileOffset);

				f = va->vm_file; // find offsets in f (file struct)
				pathOffset = (unsigned long) (&(f->f_path)) - (unsigned long) (f);
        printk(KERN_ALERT "    linux_f_path = 0x%x;\n", (unsigned int) pathOffset);

				pa = &(f->f_path); // find offsets in pa (path struct)
				dentryOffset = (unsigned long) (&(pa->dentry)) - (unsigned long) (pa);
        printk(KERN_ALERT "    linux_dentry = 0x%x;\n", (unsigned int) dentryOffset);

				d = pa->dentry; // find offsets in d (dentry struct)
				inameOffset = (unsigned long) (&(d->d_iname)) - (unsigned long) (d);
        printk(KERN_ALERT "    linux_d_iname = 0x%x;\n", (unsigned int) inameOffset);

        printk(KERN_ALERT "}\n");
    }
    else {
        printk(KERN_ALERT
               "%s: found no process to populate task_struct.\n",
               MYMODNAME);
    }

    return 0;
}

static void
my_cleanup_module(
    void)
{
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nilushan Silva");
MODULE_DESCRIPTION("task_struct offset Finder");
