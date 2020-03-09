#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for getpagesize()

#include "memory.h"

// Example line from /proc/self/maps
// 7fb804c13000-7fb804dcd000 r-xp 00000000 08:01 2888226                    /usr/lib64/libc-2.28.so
// 7f1c06ed6000-7f1c06ed8000 r-xp 00000000 08:01 4328031                    /usr/lib64/libdl-2.17.so
// typedef enum RegionTag {rt_none = 0, rt_all, rt_self, rt_libc, rt_basehook, rt_vdso, rt_vsyscall, rt_max } RegionTag;

static void initRegion(RegionPtr regionPtr, RegionTag tag, void *start, void *end, char *name) {
	// Sanity check that the world is not flat
	assert(regionPtr->tag == tag);
	assert(regionPtr->start == NULL);
	assert(regionPtr->end == NULL);
	assert(regionPtr->name[0] == '\0');

	regionPtr->start = start;
	regionPtr->end = end;
	strncpy(regionPtr->name, name, sizeof(RegionName));
} // initRegion()

void initRegions(Regions regions) {
	FILE* pMapsFile = fopen("/proc/self/maps", "r");

	// Wholesale zero the entire data structure
	bzero(regions, sizeof(Regions));

	// Initialize the tags to their appropriate values
	for (RegionTag tag = rt_none; tag < rt_max; tag++)
		regions[tag].tag = tag;

	// Scan through /proc/self/maps and collect relevant sections
	char line[1024];
	while (fgets(line, sizeof(line), pMapsFile) != NULL)
	{
		void *start, *end;
		char perm_r, perm_x;
		char name[256];

		sscanf(line, "%016lx-%016lx %c%*c%c%*c %*8c %*5c %*7c %s\n", (long unsigned int *) &start, (long unsigned int *) &end, &perm_r, &perm_x, name);
		if (perm_r == 'r' && perm_x == 'x') {
			fprintf(stdout, "scanRegions: (%016lx-%016lx) - %s\n", (long unsigned int) start, (long unsigned int) end, name);

			if (regions[rt_self].start == NULL)
				initRegion(regions + rt_self, rt_self, start, end, name);
				
        		if (strstr(name, "libc") != NULL || strstr(name, "musl") != NULL)
				initRegion(regions + rt_libc, rt_libc, start, end, name);

        		if (strstr(name, "basehook.so") != NULL)
				initRegion(regions + rt_basehook, rt_basehook, start, end, name);

        		if (strcmp(name, "[vdso]") == 0)
				initRegion(regions + rt_vdso, rt_vdso, start, end, name);

        		if (strcmp(name, "[vsyscall]") == 0)
				initRegion(regions + rt_vsyscall, rt_vsyscall, start, end, name);
		} // if
	} // while

	fclose(pMapsFile);
} // initRegions()

void printRegions(Regions regions) {
	fprintf(stdout, "printRegions:\n");
	for (RegionTag tag = rt_none; tag < rt_max; tag++)
		fprintf(stdout, "(%016lx-%016lx) - %s\n", (long unsigned int) regions[tag].start, (long unsigned int) regions[tag].end, regions[tag].name);
}

static void *searchRegion(void *start, void *end, char *name)
{
	// Don't check the special area at the top of memory called vsyscall, because it's mapped special (True?)
	if (strcmp(name, "[vsyscall]") == 0)
		return NULL;

	// In fact, don't consider anything above 0x7FFFFFFFFFFF because that's always kernel memory (True?)
	if (start > (void *) 0x800000000000 || end > (void *) 0x800000000000)
		return NULL;

	fprintf(stdout, "Search region: (%016lx-%016lx) - %s\n", (long unsigned int) start, (long unsigned int) end, name);

	FILE* pMemFile = fopen("/proc/self/mem", "r");
	int pageSize = getpagesize();

	for (void *address=start; address < end; address += pageSize)
	{
		unsigned char pages[pageSize * 2];

		fseeko(pMemFile, (off_t) address, SEEK_SET);
		size_t nBytes = fread(pages, 1, pageSize * 2, pMemFile);
	} // for

	fclose(pMemFile);

	return NULL;
} // searchRegion()

void searchMemory(void) {
	FILE* pMapsFile = fopen("/proc/self/maps", "r");

	char line[1024];
	while (fgets(line, sizeof(line), pMapsFile) != NULL)
	{
		void *start, *end;
		char perm_r, perm_x;
		char name[256];

		sscanf(line, "%016lx-%016lx %c%*c%c%*c %*8c %*5c %*7c %s\n", (long unsigned int *) &start, (long unsigned int *) &end, &perm_r, &perm_x, name);
		fprintf(stdout, "(%016lx-%016lx) - %s\n", (long unsigned int) start, (long unsigned int) end, name);
		if (perm_r == 'r' && perm_x == 'x') {
			searchRegion(start, end, name);
		} //if
	} // while

	fclose(pMapsFile);
}
