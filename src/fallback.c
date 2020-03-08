#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>

#include "fallback.h"

void fallbackGadgets(void) {
	goto beyond;
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

beyond:
	asm volatile ("nop");
} // fallbackGadgets()
