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
#define RNG_VALUE "ffffffffffffffffffffffffffffffffffff" // "f" is 0x66 in ascii
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
	uint8_t inst_byte;	// the byte stored at addr (recommend hard code in case of crash, so we can restore)
	event_response_t (*callback)(vmi_instance_t, vmi_event_t*);		// callback function to invoke after breakpoint is reached
} breakpoint_t;

unsigned int num_breakpoints; // this will be assigned later in main
breakpoint_t* breakpoints; // this will be allocated later in main
int break_idx; // set and used in callbacks as message passing interface. NOT THREAD SAFE!!!

////////////////////
// User Callbacks //
////////////////////

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
	// https://blogs.oracle.com/eschrock/entry/debugging_://blogs.oracle.com/eschrock/entry/debugging_on_amd64_part_twoon_amd64_part_tworintf("Reading R9 register: 0x%llx\n\n", register_value);	
	
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
	vmi_write_va(vmi, val_addr, 0, RNG_VALUE, EXTRACT_SIZE);

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
	printf("Got a single-step callback!\n");

	// gameplan step 5
	printf("Re-adding breakpoint before instruction.\n");
	uint8_t int3 = INT3_INST; // create temporary variable because we can't use an address to a static #defined int
	if (VMI_SUCCESS != vmi_write_8_va(vmi, breakpoints[break_idx].addr, 0, &int3)) {
		printf("Couldn't write to memory... exiting.\n");
		return VMI_FAILURE;
	}

	// clear break_idx now that we've reinserted the interrupt
	break_idx = -1;

	vmi_clear_event(vmi, event, NULL);	
	return VMI_SUCCESS;
}

event_response_t rng_int3_event_callback(vmi_instance_t vmi, vmi_event_t* event) {

	break_idx = -1;

	printf("Got an interrupt callback!\n");

	// clear reinject
	//printf("Current reinject state (1 to deliver to guest, 0 to silence): %d\n", event->interrupt_event.reinject);
	if (event->interrupt_event.reinject == -1) { // if we need to set this
		//printf("Setting reinject state to 0\n");
		event->interrupt_event.reinject = 0; // set it to silent
		//printf("Updated reinject state: %d\n", event->interrupt_event.reinject);
	}

	// iterate over breakpoints until we find the one we're at
	printf("Looking for the breakpoint for address 0x%llx\n", event->interrupt_event.gla);
	for (int i = 0; i < num_breakpoints; i++) { 
		if (event->interrupt_event.gla == breakpoints[i].addr) { // if we've found the correct breakpoint
			break_idx = i;
			printf("Found it: %d!\n", i);
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
	printf("Removing breakpoint before instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, breakpoints[break_idx].addr, 0, &(breakpoints[break_idx].inst_byte))) {
		printf("Couldn't write to memory... exiting.\n");
		return VMI_FAILURE;
	}

	// gameplan step 4
	// create singlestep event and register it
	printf("Creating singlestep event to replace breakpoint\n");
	memset(&rng_ss_event, 0, sizeof(vmi_event_t));
	rng_ss_event.type = VMI_EVENT_SINGLESTEP;
	rng_ss_event.callback = rng_single_step_callback;
	rng_ss_event.ss_event.enable = 1;
	SET_VCPU_SINGLESTEP(rng_ss_event.ss_event, event->vcpu_id);
	printf("Registering event...\n");
	if (VMI_SUCCESS == vmi_register_event(vmi, &rng_ss_event)) {; // register the event!
		printf("Event Registered!\n");
	} else { // uh oh, event failed
		printf("Problem registering singlestep event... exiting.\n");
		return VMI_FAILURE;
	}

	// we don't appear to need to clear the event (clearing event for memory, register, and single-step events)
	return VMI_SUCCESS;
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

	// this is the VM or file that we are looking at
	if (argc != 2) {
		printf("Usage: %s <vmname>\n", argv[0]);
		return 1;
	}

	char*			*sym;
  uint16_t	*off;
  addr_t		*add;
  uint8_t		*byt;

	char *name = argv[1];

	// Set up breakpoints
	num_breakpoints = 2; // set the number of breakpoints you plan to use | TODO: make this dynamic
	breakpoints = (breakpoint_t*)calloc(num_breakpoints, sizeof(breakpoint_t)); // allocate space for each breakpoint, zero memory
	// breakpoint 0 -- break after call to extract_buf, fill rng buffer with fixed values
	breakpoints[0].symbol = "extract_entropy"; // the function we're breaking on
	breakpoints[0].offset = 140; // decimal, not hex | found from static analysis of random.o
	breakpoints[0].inst_byte = 0x41; // statically found, the byte we're overwriting with the breakpoint
	breakpoints[0].callback = overwrite_buf;
	// breakpoint 1 -- break before call to extract_buf, store location of rng buffer for later use
	breakpoints[1].symbol = "extract_entropy";
	breakpoints[1].offset = 135;
	breakpoints[1].inst_byte = 0xe8;
	breakpoints[1].callback = find_buf;

	////////////////////
	// Initialization // 
	////////////////////

	// initialize the libvmi library
	printf("Initializing libvmi for VM \"%s\"\n", name);
	if (vmi_init(&vmi, VMI_XEN|VMI_INIT_COMPLETE|VMI_INIT_EVENTS, name) == VMI_FAILURE) {
		printf("Failed to init LibVMI library.\n");
		return 2;
	}

	// verify OS is Linux
	printf("Verifying the VM is running Linux...");
	// TODO: verify that the VM is running a *supported* Linux kernel
	// if kernel is not one we recognize, don't run because we'll be mucking around in memory we don't understand
	if (VMI_OS_LINUX != vmi_get_ostype(vmi)) { // this only checks if /etc/libvmi.conf says it's "Linux"
		printf("\nVM is running %s, exiting...\n", vmi_get_ostype(vmi));
		return 3;
	}
	printf(" Yup. Good to go.\n");

	// pause the vm for consistent memory access
	printf("Pausing the VM\n");
	if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
		printf("Failed to pause VM\n");
		ret_val = 4;
		goto error_exit; // don't return directly, do cleanup first
	}

	for (int i = 0; i < num_breakpoints; i++) { // iterate over breakpoints and find the right addresses for them

		////////////////////////////////////////////
		// Find memory location to put breakpoint //
		////////////////////////////////////////////

		// assign short names (note: modifying these modifies the breakpoint struct)
		sym = &breakpoints[i].symbol;
		off = &breakpoints[i].offset;
		add = &breakpoints[i].addr;
		byt = &breakpoints[i].inst_byte; // remember that if this is not set above, it should be zeroed from calloc

		// find address to break on
		printf("Accessing System Map for %s symbol\n", *sym);
		*add = vmi_translate_ksym2v(vmi, *sym) + *off;
		printf("%s + %u is at 0x%llx\n", *sym, *off, *add);

		// either verify the byte there is correct, or record which byte is there for later replacing
		if (*byt == 0) { // if this byte was not set, we need to get it
			vmi_read_8_va(vmi, *add, 0, byt); // read it directly into byt
			printf("Saving byte at address 0x%llx: %x\n", *add, *byt);
		} else { // if the byte was set, verify that it's currently set to that value
			uint8_t temp_byte = 0;
			vmi_read_8_va(vmi, *add, 0, &temp_byte); // read it temporarily
			printf("Checking byte at address 0x%llx is set to %x: %x\n", *add, *byt, temp_byte);
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
		sym = &breakpoints[i].symbol;
		off = &breakpoints[i].offset;
		add = &breakpoints[i].addr;
		byt = &breakpoints[i].inst_byte;

		// Step 1: modify memory in the VM with an INT3 instruction (0xcc)
		printf("Setting breakpoint at address 0x%llx.\n", *add);
		uint8_t int3 = INT3_INST; // create temporary variable because we can't use an address to a static #defined int
		if (VMI_SUCCESS != vmi_write_8_va(vmi, *add, 0, &int3)) {
			printf("Couldn't write INT3 instruction to memory... exiting.\n");
			ret_val = 5;
			goto error_exit;
		}

		// debug: check memory is now an INT3 instruction
		uint8_t temp_byte = 0;
		vmi_read_8_va(vmi, *add, 0, &temp_byte);
		printf("This should be an INT3 instruction (0xcc): 0x%x\n", temp_byte);


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
		sym = &breakpoints[i].symbol;
		off = &breakpoints[i].offset;
		add = &breakpoints[i].addr;
		byt = &breakpoints[i].inst_byte;

		printf("Removing breakpoint %d at 0x%llx.\n", i, *add);
		if (VMI_SUCCESS != vmi_write_8_va(vmi, *add, 0, byt)) {
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
