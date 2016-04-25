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

#define FUNC_NAME "extract_entropy"
#define EXTRACT_SIZE 10
#define RNG_VALUE "ffffffffffffffffffffffffffffffffffff" // "f" is 0x66 in ascii

vmi_event_t rng_event;
vmi_event_t rng_ss_event;

static int interrupted = 0; // set to non-zero when an interrupt happens so we can exit cleanly
static void close_handler(int signal) {
	interrupted = signal; // set interrupted to non-zero interrupt signal
}
static uint8_t cmp_replace_byte = 0x41; // not a pointer, static value
static uint8_t int3_inst = 0xcc; // not a pointer, static value
static unsigned int offset = 140; // offset into func

addr_t func = 0;
addr_t cmp = 0;

///////////////
// Callbacks // 
///////////////

event_response_t rng_single_step_callback(vmi_instance_t vmi, vmi_event_t *event) {
	printf("Got a single-step callback!\n");

	// gameplan step 5
	printf("Re-adding breakpoint before instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, cmp, 0, &int3_inst)) {
		printf("Couldn't write to memory... exiting.\n");
		return VMI_FAILURE;
	}

	vmi_clear_event(vmi, event, NULL);	
	return VMI_SUCCESS;
}

event_response_t rng_event_callback(vmi_instance_t vmi, vmi_event_t* event) {
	printf("Got a callback!\n");

	// local vars
	addr_t val_addr = 0;
	char buf[64]; // temporary buffer for local values
	
	if (event->type != VMI_EVENT_INTERRUPT) {
		printf("Wanted an interrupt event but got something else...\n");
		return VMI_FAILURE;
	}
	printf("Interrupt event!\n");
	// Print everything out
	printf("VCPU: %d\n", event->vcpu_id);
	printf("Pagetable id: %d\n", event->vmm_pagetable_id);
	printf("Instruction pointer: 0x%x\n", event->interrupt_event.gla);
	printf("Physical page of instruction: 0x%x\n", event->interrupt_event.gfn);
	printf("Page offset: 0x%x\n", event->interrupt_event.offset);
	printf("Interrupt type (1 is INT3): %d\n", event->interrupt_event.intr);
	printf("Current reinject state (1 to deliver to guest, 0 to silence): %d\n", event->interrupt_event.reinject);
	if (event->interrupt_event.reinject == -1) { // if we need to set this
		printf("Setting reinject state to 0\n");
		event->interrupt_event.reinject = 0; // set it to silent
	}
	printf("Updated reinject state: %d\n", event->interrupt_event.reinject);

	//////////////////////////
	// Access random number // 
	//////////////////////////
	
	// Print amd64 function args --> see below link for reference
	// https://blogs.oracle.com/eschrock/entry/debugging_://blogs.oracle.com/eschrock/entry/debugging_on_amd64_part_twoon_amd64_part_tworintf("Reading R9 register: 0x%llx\n\n", register_value);
	
	printf("Reading RDI register (*r):   0x%llx\n", event->regs.x86->rdi);
	printf("Reading RSP+0x16:            0x%llx  (should be the same as RSI used to be)\n", event->regs.x86->rsp+0x16);

	// modify rng buffer! (should be at RSP+0x16, from static code analysis)
	val_addr = event->regs.x86->rsp + 0x16;
	vmi_write_va(vmi, val_addr, 0, RNG_VALUE, EXTRACT_SIZE);

	// see "Main gameplan" comment section below for context
	//	3) at the end of the callback, fix the memory to its original instruction,
	//	4) single-step one instruction forward, executing the one instruction, then getting another callback
	//	5) replace the previous instruction with to 0xcc, "resetting" the breakpoint, then clearing the event and continuing

	// gameplan step 3
	printf("Removing breakpoint before instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, cmp, 0, &cmp_replace_byte)) {
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
	status_t status = VMI_SUCCESS;
	int ret_val = 0; // return code for after goto
	uint8_t* cmp_inst  = NULL; // temp buffer for value of instruction byte
	struct sigaction signal_action;

	// this is the VM or file that we are looking at
	if (argc != 2) {
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

	////////////////////////////////////////////
	// Find memory location to put breakpoint //
	////////////////////////////////////////////

	printf("Accessing System Map for %s symbol\n", FUNC_NAME);
	func = vmi_translate_ksym2v(vmi, FUNC_NAME);
	printf("%s is at 0x%x\n", FUNC_NAME, func);

	// find address of ret instruction of get_random_bytes
	// get_random_bytes does an unconditional jump into extract_entropy before invoking ret
	cmp = func+offset; // offset bytes from manual inspection of random.o in gdb

	// DEBUG: this should print "41", the first byte for the 'cmp' instruction we're interested in
	// confirm offset from extract_entropy to ret function
	cmp_inst = malloc(1);  // let's allocate a byte for this

	vmi_read_8_va(vmi, cmp, 0, cmp_inst);
	printf("This should be the first byte of the cmp instruction (0x41): 0x%x\n", *cmp_inst);

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

	// Step 1: modify memory in the VM with an INT3 instruction (0xcc)
	printf("Setting breakpoint before initial function instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, cmp, 0, &int3_inst)) {
		printf("Couldn't write INT3 instruction to memory... exiting.\n");
		ret_val = 5;
		goto error_exit;
	}

	// debug: check memory is now an INT3 instruction
	vmi_read_8_va(vmi, cmp, 0, cmp_inst);
	printf("This should be an INT3 instruction (0xcc): 0x%x\n", *cmp_inst);

	// Step 2: register an event on receiving INT3 signal
	printf("Creating event for callback when breakpoint is reached.\n");
	memset(&rng_event, 0, sizeof(vmi_event_t)); // clear rng_event so we can set everything fresh
	rng_event.type = VMI_EVENT_INTERRUPT; // interrupt event -- trigger when interrupt occurs
	rng_event.interrupt_event.intr = INT3; // trigger on INT3 instruction
	rng_event.interrupt_event.reinject = 0; // swallow interrupt silently without passing it on to guest
	rng_event.callback = rng_event_callback; // reference to our callback function
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
		status = vmi_events_listen(vmi, 500); // listen for events for 500ms (no event = VMI_SUCCESS)
		if (status != VMI_SUCCESS) {
			printf("Error waiting for events... exiting.\n");
			interrupted = -1;
		}
	}
	printf("Finished with test.\n");

	//////////////////
	// Exit cleanly // 
	//////////////////

error_exit:
	// attempt to remove breakpoint
	printf("Removing breakpoint before instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, cmp, 0, &cmp_replace_byte)) {
		printf("Couldn't write to memory... exiting.\n");
		ret_val = 7;
	}

	// debug: check memory is now a push instruction
	vmi_read_8_va(vmi, cmp, 0, cmp_inst);
	printf("This should be the restored cmp instruction byte (0x41): 0x%x\n", *cmp_inst);

	// free some malloc'd variables (if not allocated, should be NULL)
	free(cmp_inst);

	// resume the vm
	printf("Resuming the VM\n");
	vmi_resume_vm(vmi);

	// cleanup any memory associated with the LibVMI instance
	printf("Cleaning up\n");
	vmi_destroy(vmi);

	return ret_val;
}
