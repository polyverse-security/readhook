#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>

#include "addresses.h"
#include "fallback.h"
#include "memory.h"

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

void initBaseAddresses(BaseAddressesPtr bap) {
	Regions regions;
	int dummy;
	
	initRegions(regions);
	printRegions(regions);

	*bap = (BaseAddresses) {
		.buf_base    = NULL,
		.libc_base   = elfBase(strcpy),
		.fbg_base    = fallbackGadgets,
		.stack_base  = pageBase(&dummy)
	};
} // initBaseaddresses()

Pointer baseAddress(char base, BaseAddressesPtr bap) {
	switch (base) {
		case 'B' : return bap->buf_base;
		case 'L' : return bap->libc_base;
		case 'F' : return bap->fbg_base;
		case 'S' : return bap->stack_base; // Actually just base of current stack page
		default  : return 0;
	} // switch
} // baseAddress()

Offset pointerToOffset(Pointer p, char base, BaseAddressesPtr bap) {
	return (Offset) { (p - baseAddress(base, bap)), base, '~' };
} // pointerToOffset()

Offset indirectToOffset(Pointer p, char base, BaseAddressesPtr bap) {
	return (Offset) { (p - baseAddress(base, bap)), base, '*' };
} // indirectToOffset()

static Pointer offsetToPointer(Offset o, BaseAddressesPtr bap) {
	return (Pointer) (o.r + baseAddress(o.b, bap));
} // offsetToPointer()

static Pointer offsetToIndirect(Offset o, BaseAddressesPtr bap) {
	return *((Pointer *) offsetToPointer(o, bap));
} // offsetToIndirect()

AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr bap) {
	if (au.o.f == '~')
		return (AddressUnion) { .p = offsetToPointer(au.o, bap) };

	if (au.o.f == '*')
		return (AddressUnion) { .p = offsetToIndirect(au.o, bap) };

	return au;
} // fixupAddressUnion()
