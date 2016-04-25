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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define EXTRACT_SIZE 10
// "f" is 0x66 in ascii
#define RNG_VALUE "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
//#define RNG_VALUE "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii" // "i" is 0x69 in ascii
#define INT3_INST (0xCC)

vmi_event_t rng_event;
vmi_event_t rng_ss_event;

static int interrupted = 0; // set to non-zero when an interrupt happens so we can exit cleanly
static void close_handler(int signal) {
	interrupted = signal; // set interrupted to non-zero interrupt signal
}

addr_t func = 0;
addr_t cmp = 0;


typedef struct Breakpoints {
	char* symbol;				// symbol from symbol table to lookup
	uint16_t offset;		// offset from symbol to instruction
	addr_t addr;				// resulting address from symbol location + offset
	vmi_pid_t pid;			// pid of process to have breakpoint
	uint8_t inst_byte;	// the byte stored at addr (recommend hard code in case of crash, so we can restore)
	event_response_t (*callback)(vmi_instance_t, vmi_event_t*);		// callback function to invoke after breakpoint is reached
} breakpoint_t;

#define MAX_BREAKPOINTS 10
breakpoint_t* breakpoints = NULL; // this will be allocated later in main
unsigned int num_breakpoints = 0; // this will be incremented as we add breakpoints
int break_idx; // set and used in callbacks as message passing interface. NOT THREAD SAFE!!!

// temp storage for buf and nbytes
addr_t rng_buf = 0;
size_t nbytes = 0;

// offsets
unsigned long tasks_offset = 0;
unsigned long pid_offset = 0;
unsigned long name_offset = 0;
unsigned long mm_offset = 0;
unsigned long mmap_offset = 0;
unsigned long vm_area_file_offset = 0;
unsigned long vm_area_next_offset = 0;
unsigned long vm_area_start_offset = 0;
unsigned long file_path_offset = 0;
unsigned long dentry_offset = 0;
unsigned long iname_offset = 0;

////////////////////
// User Callbacks //
////////////////////

event_response_t bnrand_callback(vmi_instance_t vmi, vmi_event_t *event) {

	uint64_t nbytes;
	addr_t buf_addr;
	uint8_t* buffer;
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->regs.x86->cr3);
	printf("Called bnrand_callback from pid %d!\n");

	// look at args
	printf("Reading RDI register (*buf):    0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (bytes):    0x%llx\n", event->regs.x86->rsi);
	printf("Reading RDX register (*rnd):    0x%llx\n", event->regs.x86->rdx);

	// read in all the bytes at buf
	nbytes = event->regs.x86->rsi;
	buf_addr = event->regs.x86->rdi;
	buffer = malloc(nbytes); // allocate buffer

	vmi_read_va(vmi, buf_addr, pid, buffer, nbytes);
	printf("old buf: ");
	for (unsigned int i = 0; i < nbytes; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");

	// modify rng buffer!
	vmi_write_va(vmi, buf_addr, pid, RNG_VALUE, nbytes);

	// read in all the bytes at buf again (sanity check)
	vmi_read_va(vmi, buf_addr, pid, buffer, nbytes);
	printf("new buf: ");
	for (unsigned int i = 0; i < nbytes; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");

	return VMI_SUCCESS;
}

event_response_t before_extract_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called before_extract_buf!\n");

	// look at args
	printf("Reading RDI register (*r):      0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (*tmp):    0x%llx\n", event->regs.x86->rsi);

	// store *tmp for later overwriting
	rng_buf = event->regs.x86->rsi;

	return VMI_SUCCESS;
}
event_response_t after_extract_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called after_extract_buf!\n");

	// read in all the bytes at buf
	uint8_t buffer[EXTRACT_SIZE];

	vmi_read_va(vmi, rng_buf, 0, buffer, EXTRACT_SIZE);
	printf("old buf: ");
	for (int i = 0; i < EXTRACT_SIZE; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");

	// modify rng buffer!
	vmi_write_va(vmi, rng_buf , 0, RNG_VALUE, EXTRACT_SIZE);

	// read in all the bytes at buf again (sanity check)
	vmi_read_va(vmi, rng_buf, 0, buffer, EXTRACT_SIZE);
	printf("new buf: ");
	for (int i = 0; i < EXTRACT_SIZE; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");

	return VMI_SUCCESS;
}


event_response_t urandom_read_start(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called urandom_read_start!\n");

	// args: (struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
	printf("Reading RDI register (*file):   0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (*buf):    0x%llx\n", event->regs.x86->rsi);
	printf("Reading RDX register (nbytes):  %u\n", event->regs.x86->rdx);
	printf("Reading RCX register (*ppos):   0x%llx\n", event->regs.x86->rcx);

	// save values for later use
	rng_buf = event->regs.x86->rsi;
	nbytes = event->regs.x86->rdx;

	return VMI_SUCCESS;
}

event_response_t urandom_read_end(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called urandom_read_end!\n");

	// read in all the bytes at buf
	uint8_t buffer[nbytes];
	vmi_read_va(vmi, rng_buf, 0, buffer, nbytes);
	printf("buf: ");
	for (int i = 0; i < nbytes; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");
	
	// clear global vars
	rng_buf = 0;
	nbytes = 0;

	return VMI_SUCCESS;
}

event_response_t get_nbytes_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called get_nbytes_buf!\n");

	// get addresses for (void *buf, int nbytes) RDI, RSI
	printf("Reading RDI register (*buf):      0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (nbytes):    0x%llx\n", event->regs.x86->rsi);
	rng_buf = event->regs.x86->rdi;
	nbytes = event->regs.x86->rsi;

	return VMI_SUCCESS;
}

event_response_t check_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called check_buf!\n");

	// sanity check
	if (rng_buf == 0 || nbytes == 0) {
		printf("We don't have a buf or nbytes! AHHHHHH! 0x%llx   %u\n", rng_buf, nbytes);
	}

	// read in all the bytes at buf
	uint8_t buffer[nbytes];
	vmi_read_va(vmi, rng_buf, 0, buffer, nbytes);
	printf("buf: ");
	for (int i = 0; i < nbytes; i++) {
		printf("%02x ",buffer[i]);
	}
	printf("\n");

	return VMI_SUCCESS;
}

event_response_t find_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called find_buf!\n");

	// read registers
	printf("Reading RDI register (*r):      0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (*tmp):    0x%llx\n", event->regs.x86->rsi);
	printf("Reading RSP+0x16:               0x%llx  (should be the same as RSI)\n", event->regs.x86->rsp+0x16);
	return VMI_SUCCESS;
}

event_response_t overwrite_buf(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Called overwrite_buf!\n");
	// local vars
	addr_t val_addr = 0;
	uint8_t buf[EXTRACT_SIZE];

	// Print everything out
	//printf("VCPU: %d\n", event->vcpu_id);
	//printf("Pagetable id: %d\n", event->vmm_pagetable_id);
	//printf("Instruction pointer: 0x%x\n", event->interrupt_event.gla);
	//printf("Physical page of instruction: 0x%x\n", event->interrupt_event.gfn);
	//printf("Page offset: 0x%x\n", event->interrupt_event.offset);
	//printf("Interrupt type (1 is INT3): %d\n", event->interrupt_event.intr);

	//////////////////////////
	// Access random number // 
	//////////////////////////
	
	// Print amd64 function args --> see below link for reference
	// https://blogs.oracle.com/eschrock/entry/debugging_://blogs.oracle.com/eschrock/entry/debugging_on_amd64_part_twoon_amd64_part_two
	
	printf("Reading RDI register (*r):      0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSI register (*tmp):    0x%llx\n", event->regs.x86->rsi);
	printf("Reading RSP+0x16:               0x%llx  (should be the same as RSI)\n", event->regs.x86->rsp+0x16);

	// val_addr is our RSP+0x16
	val_addr = event->regs.x86->rsp + 0x16;

	// what's currently at RSP+0x16?
	vmi_read_va(vmi, val_addr, 0, buf, EXTRACT_SIZE);
	printf("old buf: ");
	for (int i = 0; i < EXTRACT_SIZE; i++) {
		printf("%02x ",buf[i]);
	}
	printf("\n");

	// modify rng buffer! (should be at RSP+0x16, from static code analysis)
	vmi_write_va(vmi, val_addr, 0, RNG_VALUE , EXTRACT_SIZE);

	// what's at RSP+0x16 now?
	vmi_read_va(vmi, val_addr, 0, buf, EXTRACT_SIZE);
	printf("new buf: ");
	for (int i = 0; i < EXTRACT_SIZE; i++) {
		printf("%02x ",buf[i]);
	}
	printf("\n");

	return VMI_SUCCESS;
}

//////////////////////
// LibVMI Callbacks // 
//////////////////////

event_response_t rng_single_step_callback(vmi_instance_t vmi, vmi_event_t *event) {
	//printf("Got a single-step callback!\n");

	// gameplan step 5
	//printf("Re-adding breakpoint before instruction.\n");
	uint8_t int3 = INT3_INST; // create temporary variable because we can't use an address to a static #defined int
	if (VMI_SUCCESS != vmi_write_8_va(vmi, breakpoints[break_idx].addr, 0, &int3)) {
		//printf("Couldn't write to memory... exiting.\n");
		return VMI_FAILURE;
	}

	// clear break_idx now that we've reinserted the interrupt
	break_idx = -1;

	vmi_clear_event(vmi, event, NULL);	
	return VMI_SUCCESS;
}

event_response_t rng_int3_event_callback(vmi_instance_t vmi, vmi_event_t* event) {

	break_idx = -1;

	//printf("Got an interrupt callback!\n");

	// clear reinject
	//printf("Current reinject state (1 to deliver to guest, 0 to silence): %d\n", event->interrupt_event.reinject);
	if (event->interrupt_event.reinject == -1) { // if we need to set this
		//printf("Setting reinject state to 0\n");
		event->interrupt_event.reinject = 0; // set it to silent
		//printf("Updated reinject state: %d\n", event->interrupt_event.reinject);
	}

	// iterate over breakpoints until we find the one we're at
	//printf("Looking for the breakpoint for address 0x%llx\n", event->interrupt_event.gla);
	for (int i = 0; i < num_breakpoints; i++) { 
		if (event->interrupt_event.gla == breakpoints[i].addr) { // if we've found the correct breakpoint
			break_idx = i;
			//printf("Found it: %d!\n", i);
			break;
		}
	}
	if (break_idx == -1) {
		printf("Can't find breakpoint for this instruction: 0x%llx\n",event->interrupt_event.gla);
		return VMI_FAILURE;
	}

	// call the appropriate callback
	if (VMI_SUCCESS != breakpoints[break_idx].callback(vmi, event)) {
		printf("Callback failed.\n");
		return VMI_FAILURE;
	}

	// see "Main gameplan" comment section below for context
	//	3) at the end of the callback, fix the memory to its original instruction,
	//	4) single-step one instruction forward, executing the one instruction, then getting another callback
	//	5) replace the previous instruction with to 0xcc, "resetting" the breakpoint, then clearing the event and continuing

	// gameplan step 3
	//printf("Removing breakpoint before instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, breakpoints[break_idx].addr, 0, &(breakpoints[break_idx].inst_byte))) {
		printf("Couldn't write to memory... exiting.\n");
		return VMI_FAILURE;
	}

	// gameplan step 4
	// create singlestep event and register it
	//printf("Creating singlestep event to replace breakpoint\n");
	memset(&rng_ss_event, 0, sizeof(vmi_event_t));
	rng_ss_event.type = VMI_EVENT_SINGLESTEP;
	rng_ss_event.callback = rng_single_step_callback;
	rng_ss_event.ss_event.enable = 1;
	SET_VCPU_SINGLESTEP(rng_ss_event.ss_event, event->vcpu_id);
	//printf("Registering event...\n");
	if (VMI_SUCCESS == vmi_register_event(vmi, &rng_ss_event)) {; // register the event!
		//printf("Event Registered!\n");
	} else { // uh oh, event failed
		printf("Problem registering singlestep event... exiting.\n");
		return VMI_FAILURE;
	}

	// we don't appear to need to clear the event (clearing event for memory, register, and single-step events)
	return VMI_SUCCESS;
}


///////////////////////
// Breakpoint Helper // 
///////////////////////

// helper function for creating new breakpoint
// sym:  symbol to search for
// off:  offset from symbol to set addr to
// byt:  byte to be overwritten by interrupt (set to 0 for auto-detect)
// call: callback function to call when the breakpoint executes

// NOTE: ONLY USE THIS FOR KERNEL SYMBOLS!!!
void add_breakpoint(char* sym, uint16_t off, uint8_t byt, event_response_t (*call)(vmi_instance_t, vmi_event_t*)) {
	breakpoints[num_breakpoints].symbol = sym;
	breakpoints[num_breakpoints].offset = off;
	breakpoints[num_breakpoints].addr = 0;
	breakpoints[num_breakpoints].pid = 0; // pid hardcoded to 0 because this function should only be used for kernel pid
	breakpoints[num_breakpoints].inst_byte = byt;
	breakpoints[num_breakpoints].callback = call;
	num_breakpoints++; // increment the number of breakpoints we now have
}

void add_breakpoint_addr(addr_t add, vmi_pid_t pi, uint8_t byt, event_response_t (*call)(vmi_instance_t, vmi_event_t*)) {
	breakpoints[num_breakpoints].addr = add;
	breakpoints[num_breakpoints].pid = pi;
	breakpoints[num_breakpoints].inst_byte = byt;
	breakpoints[num_breakpoints].callback = call;
	num_breakpoints++; // increment the number of breakpoints we now have
}

// Helpful resource for describing the Kernel's representation of virtual memory
// http://www.seas.ucla.edu/~uentao/spring15/CS33_1A_Week10.1.pdf
// More helpful stuff
// http://lxr.free-electrons.com/source/include/linux/sched.h#L1378
// http://lxr.free-electrons.com/source/include/linux/mm_types.h#L390
// keep following mm_types -> fs -> path -> dcache
addr_t walk_vmmap_for_lib(vmi_instance_t vmi, addr_t proc, char* libname) {
	// returns base address of first mmap'd occurrence of library
	// local vars
	addr_t mm;
	addr_t mmap;
	addr_t vm_area_st_itr;
	addr_t file;
	addr_t path;
	addr_t dentry;
	addr_t iname;
	addr_t vm_start;
	char filename[32];

	// walk the structs TODO: check each of these dereferences for errors and fail nicely
	// task_struct->mm->mmap->vm_next->vm_next->vm_next->...->vm_file->path
	vmi_read_64_va(vmi, proc + mm_offset, 0, &mm); // read address of mm
	//printf("mm is at 0x%llx\n",mm);
	vmi_read_64_va(vmi, mm + mmap_offset, 0, &mmap); // read address of first mmap in list
	//printf("mmap is at 0x%llx\n",mmap);
	vm_area_st_itr = mmap; // 
	while (vm_area_st_itr != 0) { // iterate over vm_area_structs
		vmi_read_64_va(vmi, vm_area_st_itr + vm_area_file_offset, 0, &file); // get this struct's file pointer
		//printf("file is at 0x%llx\n",file);
		path = file + file_path_offset; // not a pointer, so no need to dereference
		//printf("path is at 0x%llx\n",path);
		vmi_read_64_va(vmi, path + dentry_offset, 0, &dentry); // get dentry
		//printf("dentry is at 0x%llx\n",dentry);
		iname = dentry + iname_offset; // pointer to filename that was loaded into memory here
		//printf("iname is at 0x%llx\n",iname);
		vmi_read_va(vmi, iname, 0, filename, sizeof(filename));
		//printf("filename is %s\n",filename);
		if (strncmp(filename, libname, sizeof(libname)) == 0) { // if we've found the lib
			vmi_read_64_va(vmi, vm_area_st_itr + vm_area_start_offset, 0, &vm_start); // grab address of start of memory-mapped region
			//printf("base address of memory is 0x%llx\n", vm_start);
			return vm_start;
		}

		// go to next
		vmi_read_64_va(vmi, vm_area_st_itr + vm_area_next_offset, 0, &vm_area_st_itr);
	} 
	return 0; // Failure
}

//////////
// Main // 
//////////

int main (int argc, char **argv)
{
	// local variables
	vmi_instance_t vmi;
	int ret_val = 0; // return code for after goto
	struct sigaction signal_action;

	// process list vars
	vmi_pid_t pid = 0;
	char *procname = NULL;
	addr_t list_head = 0;
	addr_t next_list_entry = 0;
	addr_t current_process = 0;
	addr_t tmp_next = 0;
	status_t status;

	// breakpoint vars
	char*			*sym;
	uint16_t	*off;
	vmi_pid_t *bpid;
	addr_t		*add;
	uint8_t		*byt;

	addr_t lib_map_addr = 0;
	addr_t BN_rand_addr = 0;
	int bnrand_jump_offset = 0;
	addr_t bnrand_addr = 0;

	// this is the VM or file that we are looking at
	if (argc < 2) {
		printf("Usage: %s <vmname>\n", argv[0]);
		return 1;
	}
	
	char *name = argv[1];

	////////////////////
	// Initialization // 
	////////////////////

	// initialize the libvmi library
	printf("Initializing libvmi for VM \"%s\"\n", name);
	if (vmi_init(&vmi, VMI_XEN|VMI_INIT_COMPLETE|VMI_INIT_EVENTS, name) == VMI_FAILURE) {
		printf("Failed to init LibVMI library.\n");
		ret_val = 2;
		goto error_exit;
	}

	// verify OS is Linux
	printf("Verifying the VM is running Linux...");
	// TODO: verify that the VM is running a *supported* Linux kernel
	// if kernel is not one we recognize, don't run because we'll be mucking around in memory we don't understand
	if (VMI_OS_LINUX != vmi_get_ostype(vmi)) { // this only checks if /etc/libvmi.conf says it's "Linux"
		printf("\nVM is running %s, exiting...\n", vmi_get_ostype(vmi));
		ret_val = 3;
		goto error_exit;
	}
	printf(" Yup. Good to go.\n");

	// pause the vm for consistent memory access
	printf("Pausing the VM\n");
	if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
		printf("Failed to pause VM\n");
		ret_val = 4;
		goto error_exit; // don't return directly, do cleanup first
	}

	tasks_offset					= vmi_get_offset(vmi, "linux_tasks");
	name_offset						= vmi_get_offset(vmi, "linux_name");
	pid_offset						= vmi_get_offset(vmi, "linux_pid");
	mm_offset							= vmi_get_offset(vmi, "linux_mm");
	// hardcoded because config_parser doesn't support dynamic config vars
	mmap_offset						= 0x0;
	vm_area_file_offset		= 0xa0;
	vm_area_next_offset		= 0x10;
	vm_area_start_offset	= 0x0;
	file_path_offset			= 0x10;
	dentry_offset					= 0x8;
	iname_offset					= 0x38;
	//mmap_offset = vmi_get_offset(vmi, "linux_mmap");
	//vm_area_file_offset = vmi_get_offset(vmi, "linux_vm_file");
	//vm_area_next_offset = vmi_get_offset(vmi, "linux_vm_next");
	//vm_area_start_offset = vmi_get_offset(vmi, "linux_vm_start");
	//file_path_offset = vmi_get_offset(vmi, "linux_f_path");
	//dentry_offset = vmi_get_offset(vmi, "linux_dentry");
	//iname_offset = vmi_get_offset(vmi, "linux_d_iname");

	if (0 == tasks_offset) {
		printf("Failed to find tasks_offset\n");
		goto error_exit;
	}   
	if (0 == pid_offset) {
		printf("Failed to find pid_offset\n");
		goto error_exit;
	}   
	if (0 == name_offset) {
		printf("Failed to find name_offset\n");
		goto error_exit;
	}   
	if (0 == mm_offset) {
		printf("Failed to find mm_offset\n");
		goto error_exit;
	}   
	//if (0 == mmap_offset) {
	//	printf("Failed to find mmap_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == vm_area_file_offset) {
	//	printf("Failed to find vm_area_file_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == vm_area_next_offset) {
	//	printf("Failed to find vm_area_next_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == vm_area_start_offset) {
	//	printf("Failed to find vm_area_start_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == file_path_offset) {
	//	printf("Failed to find file_path_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == dentry_offset) {
	//	printf("Failed to find dentry_offset\n");
	//	goto error_exit;
	//}   
	//if (0 == iname_offset) {
	//	printf("Failed to find iname_offset\n");
	//	goto error_exit;
	//}   

	// Set up breakpoints
	breakpoints = (breakpoint_t*)calloc(MAX_BREAKPOINTS, sizeof(breakpoint_t)); // allocate space for each breakpoint, zero memory
	//add_breakpoint("extract_entropy_user", 155, 0, 0xe8, before_extract_buf);
	//add_breakpoint("extract_entropy_user", 160, 0, 0x83, after_extract_buf);
	// new breakpoints created below

	//////////////////////////
	// Find apache2 process //
	//////////////////////////

	// find pid of apache2 processes
	// for each process, read symbol table and find BN_rand function
	// at offset +13 bytes from BN_rand, we find an offset from the instruction at BN_rand+17 (probably around -700 bytes)
	// +570 bytes from the offset above, we find the instruction at which we want a breakpoint
	// so, breakpoint at BN_rand+17+[BN_rand+13]+570
	// then, at callback, read r13 for address of buffer, overwrite with TODO bytes

	// find pid of apache2 processes
	list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset; // find init_task struct and move to first linked list entry
	next_list_entry = list_head; // iterator
	do {
		current_process = next_list_entry - tasks_offset; // subtract tasks_offset back off to get to head of struct
		vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid); // get pid of this process
		procname = vmi_read_str_va(vmi, current_process + name_offset, 0); // get process name of this process
		if (strncmp(procname,"apache2",sizeof("apache2")) == 0) {
			printf("Finding library address in %s [pid %d]\n",procname,pid);
			lib_map_addr = walk_vmmap_for_lib(vmi, current_process, "libcrypto.so.1.0.2");
			if (lib_map_addr == 0) { // if failed to find lib
				printf("Failed to find library in %s\n",procname);
				ret_val = 9;
				goto error_exit;
			}
			printf("Found library address: 0x%llx\n", lib_map_addr);
			// for each process, read symbol table and find BN_rand function
			BN_rand_addr = lib_map_addr + 0xd5a50; // static offset for BN_rand function
			// at offset +13 bytes from BN_rand, we find an offset from the instruction at BN_rand+17 (probably around -700 bytes)
			vmi_read_32_va(vmi, BN_rand_addr+13, pid, &bnrand_jump_offset); // get jump offset to bnrand function
			//printf("jump offset: %d\n",bnrand_jump_offset);
			bnrand_addr = BN_rand_addr+17+bnrand_jump_offset; // get address of bnrand function
			//printf("bnrand: 0x%llx\n", bnrand_addr);
			// +570 bytes from the offset above, we find the instruction at which we want a breakpoint
			add_breakpoint_addr(bnrand_addr + 570, pid, 0x31, bnrand_callback);
			//printf("Added breakpoint at 0x%llx\n",bnrand_addr+570);
		}
		status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry); // follow linked-list->next to next element
		if (status == VMI_FAILURE) {
			printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
			goto error_exit;
		}

	} while(next_list_entry != list_head);




	for (int i = 0; i < num_breakpoints; i++) { // iterate over breakpoints and find the right addresses for them

		////////////////////////////////////////////
		// Find memory location to put breakpoint //
		////////////////////////////////////////////

		// assign short names (note: modifying these modifies the breakpoint struct)
		sym = &breakpoints[i].symbol;
		off = &breakpoints[i].offset;
		bpid = &breakpoints[i].pid;
		add = &breakpoints[i].addr;
		byt = &breakpoints[i].inst_byte; // remember that if this is not set above, it should be zeroed from calloc

		if (breakpoints[i].addr == 0) { // if don't have address, find symbol
			// find address to break on
			printf("Accessing System Map for %s symbol\n", *sym);
			*add = vmi_translate_ksym2v(vmi, *sym) + *off;
			printf("%s + %u is at 0x%llx\n", *sym, *off, *add);
		}

		// either verify the byte there is correct, or record which byte is there for later replacing
		if (*byt == 0) { // if this byte was not set, we need to get it
			vmi_read_8_va(vmi, *add, *bpid, byt); // read it directly into byt
			printf("[pid %d] Saving byte at address 0x%llx: %x\n", *bpid, *add, *byt);
		} else { // if the byte was set, verify that it's currently set to that value
			uint8_t temp_byte = 0;
			vmi_read_8_va(vmi, *add, *bpid, &temp_byte); // read it temporarily
			printf("[pid %d] Checking byte at address 0x%llx is set to %x: %x\n", *bpid, *add, *byt, temp_byte);
			if (*byt != temp_byte) { // uh oh, we have an error
				ret_val = 8;
				goto error_exit;
			}
		}
	} // end first for loop after breakpoints are constructed properly

	///////////////////
	// Main gameplan //
	//               //
	// https://groups.google.com/forum/#!topic/vmitools/jNGxM0LBEDM
	// Based on the google groups discussion above (which I wish I found earlier, meh), it looks like the way people trap on instructions is to:
	//	1) actually *modify* the memory to have the 0xcc (interrupt 3, aka breakpoint) instruction in place of the instruction it would have executed
	//	2) register an event on receiving the INT3 signal and receive the callback
	//	3) at the end of the callback, fix the memory to its original instruction,
	//	4) single-step one instruction forward, executing the one instruction, then getting another callback
	//	5) replace the previous instruction with to 0xcc, "resetting" the breakpoint, then clearing the event and continuing
	//               //
	///////////////////

	for (int i = 0; i < num_breakpoints; i++) { // iterate over breakpoints and insert them all

		// assign short names (note: modifying these modifies the breakpoint struct)
		add = &breakpoints[i].addr;
		bpid = &breakpoints[i].pid;
		byt = &breakpoints[i].inst_byte;

		// Step 1: modify memory in the VM with an INT3 instruction (0xcc)
		printf("[pid %d] Setting breakpoint at address 0x%llx.\n", *bpid, *add);
		uint8_t int3 = INT3_INST; // create temporary variable because we can't use an address to a static #defined int
		if (VMI_SUCCESS != vmi_write_8_va(vmi, *add, *bpid, &int3)) {
			printf("[pid %d] Couldn't write INT3 instruction to memory... exiting.\n", *bpid);
			ret_val = 5;
			goto error_exit;
		}

		// debug: check memory is now an INT3 instruction
		uint8_t temp_byte = 0;
		vmi_read_8_va(vmi, *add, 0, &temp_byte);
		printf("[pid %d] This should be an INT3 instruction (0xcc): 0x%x\n", *bpid, temp_byte);


	} // end second for loop after breakpoints are all inserted and callback is registered

	// Step 2: register an event on receiving INT3 signal
	printf("Creating event for callback when breakpoint is reached.\n");
	memset(&rng_event, 0, sizeof(vmi_event_t)); // clear rng_event so we can set everything fresh
	rng_event.type = VMI_EVENT_INTERRUPT; // interrupt event -- trigger when interrupt occurs
	rng_event.interrupt_event.intr = INT3; // trigger on INT3 instruction
	rng_event.interrupt_event.reinject = 0; // swallow interrupt silently without passing it on to guest
	rng_event.callback = rng_int3_event_callback; // reference to our callback function
	printf("Registering event...\n");
	if (VMI_SUCCESS == vmi_register_event(vmi, &rng_event)) {; // register the event!
		printf("Event Registered!\n");
	} else { // uh oh, event failed
		printf("Problem registering event... exiting.\n");
		ret_val = 6;
		goto error_exit; // don't return directly, do cleanup first
	}

	// resume the VM
	printf("Resuming the VM\n");
	vmi_resume_vm(vmi);

	//////////////////////////////////////
	// Spin and wait for event callback // 
	//////////////////////////////////////

	// for a clean exit, catch signals (from host, not VM), set "interrupted" to non-zero, exit while loop at end of main()
	signal_action.sa_handler = close_handler;
	signal_action.sa_flags = 0;
	sigemptyset(&signal_action.sa_mask);
	sigaction(SIGHUP,  &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	sigaction(SIGINT,  &signal_action, NULL);
	sigaction(SIGALRM, &signal_action, NULL);

	while(!interrupted) { // until an interrupt happens
		printf("Waiting for events...\n");
		if (VMI_SUCCESS != vmi_events_listen(vmi, 500)) { // listen for events for 500ms (no event = VMI_SUCCESS)
			printf("Error waiting for events... exiting.\n");
			interrupted = -1;
		}
	}
	printf("Finished with test.\n");

	//////////////////
	// Exit cleanly // 
	//////////////////

error_exit:
	// attempt to remove breakpoints
	for (int i = 0; i < num_breakpoints; i++) { // iterate over breakpoints and insert them all

		// assign short names (note: modifying these modifies the breakpoint struct)
		add = &breakpoints[i].addr;
		bpid = &breakpoints[i].pid;
		byt = &breakpoints[i].inst_byte;

		printf("[pid %d] Removing breakpoint %d at 0x%llx.\n", *bpid, i, *add);
		if (VMI_SUCCESS != vmi_write_8_va(vmi, *add, *bpid, byt)) {
			printf("Couldn't write to memory... exiting.\n");
			ret_val = 7;
		}
	}

	// resume the vm
	printf("Resuming the VM\n");
	vmi_resume_vm(vmi);

	// cleanup any memory associated with the LibVMI instance
	printf("Cleaning up\n");
	vmi_destroy(vmi);

	return ret_val;
}
