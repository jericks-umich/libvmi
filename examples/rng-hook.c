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

#define FUNC_NAME1 "get_random_bytes"
#define FUNC_NAME2 "extract_entropy"

vmi_event_t rng_event;

static int interrupted = 0; // set to non-zero when an interrupt happens so we can exit cleanly
static void close_handler(int signal) {
	interrupted = signal; // set interrupted to non-zero interrupt signal
}

//////////////
// Callback // 
//////////////

event_response_t rng_event_callback(vmi_instance_t vmi, vmi_event_t* event) {
	printf("Got a callback!\n");

	// local vars
	addr_t test = 0;
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
	printf("RSP: 0x%llx\n", event->regs.x86->rsp);
	printf("RBP: 0x%llx\n", event->regs.x86->rbp);
	// at the point we've set a breakpoint, we've got rsp -> r15 saved value. Above that should be the return address.
	test = event->regs.x86->rsp;
	printf("Reading r15 bytes at: 0x%llx\n", test);
	vmi_read_64_va(vmi, test, 0, (uint64_t*)buf);
	printf("0x%llx\n", *(uint64_t*)buf);
	test += 8;
	printf("Reading ret bytes at: 0x%llx\n", test);
	vmi_read_64_va(vmi, test, 0, (uint64_t*)buf);
	printf("0x%llx\n", *(uint64_t*)buf);
	test += 8;
	printf("Reading 4 bytes at: 0x%llx\n", test);
	vmi_read_32_va(vmi, test, 0, (uint32_t*)buf);
	printf("0x%x\n", *(uint32_t*)buf);
	test += 4;
	printf("Reading 4 bytes at: 0x%llx\n", test);
	vmi_read_32_va(vmi, test, 0, (uint32_t*)buf);
	printf("0x%x\n", *(uint32_t*)buf);
	test += 4;
	printf("Reading bytes at: 0x%llx\n", test);
	vmi_read_64_va(vmi, test, 0, (uint64_t*)buf);
	printf("0x%llx\n", *(uint64_t*)buf);
	test += 8;
	printf("Reading bytes at: 0x%llx\n", test);
	vmi_read_64_va(vmi, test, 0, (uint64_t*)buf);
	printf("0x%llx\n", *(uint64_t*)buf);
	test += 8;
	printf("Reading bytes at: 0x%llx\n", test);
	vmi_read_64_va(vmi, test, 0, (uint64_t*)buf);
	printf("0x%llx\n", *(uint64_t*)buf);
	

	// see "Main gameplan" comment section below for context
	//	3) at the end of the callback, fix the memory to its original instruction,
	//	4) single-step one instruction forward, executing the one instruction, then getting another callback
	//	5) replace the previous instruction with to 0xcc, "resetting" the breakpoint, then clearing the event and continuing


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
	addr_t func1 = 0;
	addr_t func2 = 0;
	addr_t ret = 0;
	addr_t pop = 0;
	uint8_t* ret_inst  = NULL;
	uint8_t* pop_inst  = NULL;
	uint8_t pop_replace_inst = 0x41; // not a pointer, static value
	uint8_t int3_inst = 0xcc; // not a pointer, static value
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

	printf("Accessing System Map for %s symbol\n", FUNC_NAME1);
	func1 = vmi_translate_ksym2v(vmi, FUNC_NAME1);
	printf("%s is at 0x%x\n", FUNC_NAME1, func1);

	printf("Accessing System Map for %s symbol\n", FUNC_NAME2);
	func2 = vmi_translate_ksym2v(vmi, FUNC_NAME2);
	printf("%s is at 0x%x\n", FUNC_NAME2, func2);

	// find address of ret instruction of get_random_bytes
	// get_random_bytes does an unconditional jump into extract_entropy before invoking ret
	ret  = func2+251; // 251 bytes from manual inspection of random.o in gdb
	pop  = func2+249; // 249 bytes from manual inspection of random.o in gdb

	// DEBUG: this should print "c3" the byte for a 'ret' instruction
	// confirm offset from extract_entropy to ret function
	ret_inst = malloc(1);  // let's allocate a byte for this
	pop_inst = malloc(1);  // let's allocate a byte for this

	vmi_read_8_va(vmi, ret, 0, ret_inst);
	vmi_read_8_va(vmi, pop, 0, pop_inst);
	printf("This should be a return instruction (0xc3): 0x%x\n", *ret_inst); // should be 0xc3
	printf("This should be the first byte of a pop r15 instruction (0x41): 0x%x\n", *pop_inst); // should be 0x41

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
	printf("Setting breakpoint before return instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, pop, 0, &int3_inst)) {
		printf("Couldn't write INT3 instruction to memory... exiting.\n");
		ret_val = 5;
		goto error_exit;
	}

	// debug: check memory is now an INT3 instruction
	vmi_read_8_va(vmi, pop, 0, pop_inst);
	printf("This should be an INT3 instruction (0xcc): 0x%x\n", *pop_inst);

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
	printf("Removing breakpoint before return instruction.\n");
	if (VMI_SUCCESS != vmi_write_8_va(vmi, pop, 0, &pop_replace_inst)) {
		printf("Couldn't write to memory... exiting.\n");
		ret_val = 7;
	}

	// debug: check memory is now a pop instruction
	vmi_read_8_va(vmi, pop, 0, pop_inst);
	printf("This should be the restored pop instruction byte (0x41): 0x%x\n", *pop_inst);

	// free some malloc'd variables (if not allocated, should be NULL)
	free(ret_inst);
	free(pop_inst);

	// resume the vm
	printf("Resuming the VM\n");
	vmi_resume_vm(vmi);

	// cleanup any memory associated with the LibVMI instance
	printf("Cleaning up\n");
	vmi_destroy(vmi);

	return ret_val;
}

/*
	// create and register event
	// checking out SETUP_MEM_EVENT macro in events.h helps explain this (and also check out ENUMs in events.h)
	printf("Creating event for callback when return instruction is executed.\n");
	memset(&rng_event, 0, sizeof(vmi_event_t)); // clear rng_event so we can set everything fresh
	rng_event.type = VMI_EVENT_MEMORY; // memory event -- trigger when memory address is executed
	rng_event.mem_event.physical_address = ret; // set the address to trigger on to our identified return instruction
	rng_event.mem_event.granularity = VMI_MEMEVENT_BYTE; // trigger on byte access, not page access (which would be VMI_EVENT_PAGE)
	rng_event.mem_event.in_access = VMI_MEMACCESS_X; // trigger on execute, not read or write (we want to introspect when the ret is executed)
	rng_event.mem_event.npages = 1; // documented as "reserved". Not sure what this does, but 1 is the default value in events.h and also what is used in event-example.c
	rng_event.callback = rng_event_callback; // reference to our callback function
	printf("Registering event...\n");
	if (VMI_SUCCESS == vmi_register_event(vmi, &rng_event)) {; // register the event!
		printf("Event Registered!\n");
	} else { // uh oh, event failed
		printf("Problem registering event... exiting.\n");
		ret_val = 5;
		goto error_exit; // don't return directly, do cleanup first
	}
*/
