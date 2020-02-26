#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "addresses.h"

static Pointer pageBase(Pointer p) {
	return (Pointer) (((unsigned long) p) & (-1 ^ getpagesize() - 1));
} // pageBase()

static Pointer elfBase(Pointer p) {
	const char s_elf_signature[] = {0x7F, 'E', 'L', 'F', 0};

	p = pageBase(p);
	while (strncmp(p, s_elf_signature, strlen(s_elf_signature)))
		p -= getpagesize();

	return p;
} // elfBase()

void initBaseAddresses(BaseAddressesPtr baseAddressesPtr) {
	int dummy;

	*baseAddressesPtr = (BaseAddresses) {
		.buf_base    = NULL,
		.libc_base   = elfBase(strcpy),
		.fbg_base    = fallbackGadgets,
		.stack_base  = pageBase(&dummy)
	};
} // initBaseaddresses()

Pointer baseAddress(char base, BaseAddressesPtr baseAddressesPtr) {
	switch (base) {
		case 'B' : return baseAddressesPtr->buf_base;
		case 'L' : return baseAddressesPtr->libc_base;
		case 'F' : return baseAddressesPtr->fbg_base;
		case 'S' : return baseAddressesPtr->stack_base; // Actually just base of current stack page
		default  : return 0;
	} // switch
} // baseAddress()

Offset pointerToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '~' };
} // pointerToOffset()

Offset indirectToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '*' };
} // indirectToOffset()

static Pointer offsetToPointer(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return (Pointer) (o.r + baseAddress(o.b, baseAddressesPtr));
} // offsetToPointer()

static Pointer offsetToIndirect(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return *((Pointer *) offsetToPointer(o, baseAddressesPtr));
} // offsetToIndirect()

AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr baseAddressesPtr) {
	if (au.o.f == '~')
		return (AddressUnion) { .p = offsetToPointer(au.o, baseAddressesPtr) };

	if (au.o.f == '*')
		return (AddressUnion) { .p = offsetToIndirect(au.o, baseAddressesPtr) };

	return au;
} // fixupAddressUnion()

// This function MUST return a malloc()'ed block of memory to avoid stack corruption (it's ok, the program's getting pwned).
Pointer dofixups(Pointer src, size_t n, BaseAddressesPtr baseAddressesPtr) {
	size_t nAUP = n - sizeof(AddressUnionPtr) + 1;
	AddressUnionPtr srcAUP = (AddressUnionPtr) src;
	AddressUnionPtr dstAUP = (AddressUnionPtr) calloc(nAUP, sizeof(AddressUnion));

	for (size_t i = 0; i < nAUP; i++)
		dstAUP[i] = fixupAddressUnion(srcAUP[i], baseAddressesPtr);

	return (Pointer) dstAUP;
} // dofixups()

void fallbackGadgets(void) {
	// Fallback gadget for "POP RDI"
	asm volatile ("pop %rdi");
	asm volatile ("ret");

	// Fallback gadget for "POP RSI"
	asm volatile ("pop %rsi");
	asm volatile ("ret");

	// Fallback gadget for "POP RDX"
	asm volatile ("pop %rdx");
	asm volatile ("ret");

	// NOP gadget for creating a dependency
	asm volatile ("nop");
	asm volatile ("ret");
} // fallbackGadgets()
