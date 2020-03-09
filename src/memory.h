#ifndef _MEMORY_H_
#define _MEMORY_H_

typedef enum RegionTag {rt_none = 0, rt_self, rt_libc, rt_basehook, rt_vdso, rt_vsyscall, rt_max } RegionTag;

typedef char RegionName[256];

typedef struct Region {
	RegionTag  tag;
	void       *start;
	void       *end;
	RegionName name;
} Region, *RegionPtr;

typedef Region Regions[rt_max];

extern void initRegions(Regions regions);
extern void printRegions(Regions regions);
extern void *searchRegion(RegionPtr regionPtr, char *searchString);
extern void *searchMemory(char *searchString);

#endif
