#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h> // for getpagesize()

#include "memory.h"

// Example line from /proc/self/maps
// 7fb804c13000-7fb804dcd000 r-xp 00000000 08:01 2888226                    /usr/lib64/libc-2.28.so
// 7f1c06ed6000-7f1c06ed8000 r-xp 00000000 08:01 4328031                    /usr/lib64/libdl-2.17.so


static void *searchRegion(FILE* pMemFile, void *start, void *end, char *name)
{
	int pageLength = getpagesize();
	unsigned char page[pageLength];
	fseeko(pMemFile, (off_t) start, SEEK_SET);

	// Don't check the special area at the top of memory called vsyscall, because it's mapped special (True?)
	if (strcmp(name, "[vsyscall]") == 0)
		return NULL;

	// In fact, don't consider anything above 0x7FFFFFFFFFFF because that's always kernel memory (True?)
	if (start > (void *) 0x800000000000 || end > (void *) 0x800000000000)
		return NULL;

	fprintf(stdout, "Search region: (%016lx-%016lx) - %s\n", start, end, name);

	for (void *address=start; address < end; address += pageLength)
	{
		fread(&page, 1, pageLength, pMemFile);
//		fwrite(&page, 1, pageLength, stdout);
	} // for

	return NULL;
} // searchRegion()

void searchMemory(void) {

	FILE* pMapsFile = fopen("/proc/self/maps", "r");
	FILE* pMemFile = fopen("/proc/self/mem", "r");

	char line[1024];
	while (fgets(line, sizeof(line), pMapsFile) != NULL)
	{
		void *start, *end;
		char perm_r, perm_x;
		char name[256];

		sscanf(line, "%016lx-%016lx %c%*c%c%*c %*8c %*5c %*7c %s\n", &start, &end, &perm_r, &perm_x, name);
//		fprintf(stdout, "(%016lx-%016lx) - %s\n", start, end, name);
		if (perm_r == 'r' && perm_x == 'x') {
			searchRegion(pMemFile, start, end, name);
		} //if
	} // while

	fclose(pMapsFile);
	fclose(pMemFile);
}

