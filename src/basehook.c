#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// For dlsym()
#include <stdio.h>	// For i/o
#include <string.h>	// For str...() and mem...()
#include <errno.h>

#include "payload.h"
#include "base64.h"
#include "strnstr.h"

static const char s_basemagic[]	= "xyzzy";
static const char s_overflow[]	= "OVERFLOW";

static void *libc_handle = NULL;

static void init() __attribute__((constructor));
void init() {
	libc_handle = dlopen("libc.so.6",RTLD_LAZY);
	// NOTE: libc.so.6 may *not* exist on Alpha and IA-64 architectures.
	if(!libc_handle) {
		fprintf(stderr,"basehook.so init(): libc.so.6 dlopen() failed");
		errno = ENOENT;
	} else {
		fprintf(stderr,"basehook.so init(): libc.so.6 opened");
	}
}

// This is the overflow that readhook is all about.
static void overflow(Pointer src, size_t n, BaseAddressesPtr bap) {
        char buffer[8] = {'E', '-', 'E', 'G', 'G', ' ', ' ', 0 };

	bap->buf_base = &buffer;
	Pointer dst = dofixups(src, n, bap); // If you don't need this call, you're a fscking awesome hacker. Respect!
	memcpy(buffer, dst, n);
} // overflow()

// Interloper read function that watches for the magic string.
typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	// Read *libc_read = (Read *) dlsym(RTLD_NEXT, "read"); 
	// fprintf(stderr,"basehook.so read(%d)", fd);
	Read *libc_read = (Read *) dlsym(libc_handle,"read");
	if(!libc_read) {
	// Bad! 'read' was not found inside libc.
		return -1;
		errno = EINVAL;
	}	
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < (ssize_t) strlen(s_basemagic)) ? NULL : strnstr(buf, s_basemagic, result);

	if (p) {
		p += strlen(s_basemagic);

		BaseAddresses baseAddresses;
		initBaseAddresses(&baseAddresses);

		 if (!strncmp(s_overflow, p, strlen(s_overflow))) {
			unsigned char *s64 = (unsigned char *) (p + strlen(s_overflow));
			size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) p, 65535); // ToDo: Unknown upper bounds
			overflow(p, n256, &baseAddresses);
		} // if
	} // if

	return result;
} // read()
