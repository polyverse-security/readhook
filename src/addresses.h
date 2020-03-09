#ifndef _ADDRESSES_H_
#define _ADDRESSES_H_
#include <stddef.h>

#include "memory.h"

typedef void *Pointer;

typedef struct Offset {
	long	r : 48;
	char	b : 8;
	char	f : 8;
} Offset, *OffsetPtr;

typedef union AddressUnion {
	Pointer	p;
	Offset	o;
	char	c[sizeof(Pointer)];
} AddressUnion, *AddressUnionPtr;

typedef struct BaseAddresses {
	Regions regions;
	Pointer buf_base;
	Pointer libc_base;
	Pointer fbg_base;
	Pointer stack_base;
} BaseAddresses, *BaseAddressesPtr;

extern void         initBaseAddresses(BaseAddressesPtr baseAddresses);
extern Pointer      baseAddress(char base, BaseAddressesPtr bap);
extern Offset       pointerToOffset(Pointer p, char base, BaseAddressesPtr bap);
extern Offset       indirectToOffset(Pointer p, char base, BaseAddressesPtr bap);
extern AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr bap);
#endif
