#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "addresses.h"
#include "fallback.h"

static Pointer pageBase(Pointer p) {
	return (Pointer) (((unsigned long) p) & (-1 ^ getpagesize() - 1));
} // pageBase()

void initBaseAddresses(BaseAddressesPtr bap) {
	int dummy;
	
	initRegions(bap->regions);
	printRegions(bap->regions);

        // Make sure that we found what we expect
        for (RegionTag tag = rt_none + 1; tag < rt_max; tag++)
                assert(bap->regions[tag].start != NULL && bap->regions[tag].end != NULL);

	// Make sure, that strcpy() is in the libc region
	assert(bap->regions[rt_libc].start < (void *) strcpy);
	assert(bap->regions[rt_libc].end   > (void *) strcpy);

	// Make sure that fallbackGadgets() is in the basehook region
	assert(bap->regions[rt_basehook].start < (void *) fallbackGadgets);
	assert(bap->regions[rt_basehook].end   > (void *) fallbackGadgets);

	bap->buf_base   = NULL;
	bap->stack_base = pageBase(&dummy);
} // initBaseaddresses()

Pointer baseAddress(char base, BaseAddressesPtr bap) {
	switch (base) {
		case 'B' : return bap->buf_base;
		case 'L' : return bap->regions[rt_libc].start;
		case 'F' : return bap->regions[rt_basehook].start;
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
