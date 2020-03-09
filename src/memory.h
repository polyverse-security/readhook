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
extern void searchMemory(void);

// "", "<ALL>", "fullhook", "libc-2.17.so", "basehook.so", "[vdso]", "[vsyscall]"
#if 0 // Alpine
(0000561163d66000-0000561163d67000) - /readhook/app/fullhook
(0000561163d67000-0000561163d6a000) - /readhook/app/fullhook
Search region: (0000561163d67000-0000561163d6a000) - /readhook/app/fullhook
(0000561163d6a000-0000561163d6b000) - /readhook/app/fullhook
(0000561163d6b000-0000561163d6c000) - /readhook/app/fullhook
(0000561163d6c000-0000561163d6d000) - /readhook/app/fullhook
(00007f222ca71000-00007f222ca72000) - /readhook/dll/basehook.so
(00007f222ca72000-00007f222ca75000) - /readhook/dll/basehook.so
Search region: (00007f222ca72000-00007f222ca75000) - /readhook/dll/basehook.so
(00007f222ca75000-00007f222ca76000) - /readhook/dll/basehook.so
(00007f222ca76000-00007f222ca77000) - /readhook/dll/basehook.so
(00007f222ca77000-00007f222ca78000) - /readhook/dll/basehook.so
(00007f222ca78000-00007f222ca8d000) - /lib/ld-musl-x86_64.so.1
(00007f222ca8d000-00007f222cad3000) - /lib/ld-musl-x86_64.so.1
Search region: (00007f222ca8d000-00007f222cad3000) - /lib/ld-musl-x86_64.so.1
(00007f222cad3000-00007f222cb07000) - /lib/ld-musl-x86_64.so.1
(00007f222cb08000-00007f222cb09000) - /lib/ld-musl-x86_64.so.1
(00007f222cb09000-00007f222cb0a000) - /lib/ld-musl-x86_64.so.1
(00007f222cb0a000-00007f222cb0d000) - /lib/ld-musl-x86_64.so.1
(00007fff052c2000-00007fff052e3000) - [stack]
(00007fff0534a000-00007fff0534d000) - [vvar]
(00007fff0534d000-00007fff0534f000) - [vdso]
Search region: (00007fff0534d000-00007fff0534f000) - [vdso]
(ffffffffff600000-ffffffffff601000) - [vsyscall]
#endif 

#if 0 // Centos
(000056316da23000-000056316da28000) - /readhook/app/fullhook
Search region: (000056316da23000-000056316da28000) - /readhook/app/fullhook
(000056316dc27000-000056316dc28000) - /readhook/app/fullhook
(000056316dc28000-000056316dc29000) - /readhook/app/fullhook
(000056316e68e000-000056316e6af000) - [heap]
(00007f84e9c4d000-00007f84e9c4f000) - /usr/lib64/libdl-2.17.so
Search region: (00007f84e9c4d000-00007f84e9c4f000) - /usr/lib64/libdl-2.17.so
(00007f84e9c4f000-00007f84e9e4f000) - /usr/lib64/libdl-2.17.so
(00007f84e9e4f000-00007f84e9e50000) - /usr/lib64/libdl-2.17.so
(00007f84e9e50000-00007f84e9e51000) - /usr/lib64/libdl-2.17.so
(00007f84e9e51000-00007f84ea014000) - /usr/lib64/libc-2.17.so
Search region: (00007f84e9e51000-00007f84ea014000) - /usr/lib64/libc-2.17.so
(00007f84ea014000-00007f84ea214000) - /usr/lib64/libc-2.17.so
(00007f84ea214000-00007f84ea218000) - /usr/lib64/libc-2.17.so
(00007f84ea218000-00007f84ea21a000) - /usr/lib64/libc-2.17.so
(00007f84ea21a000-00007f84ea21f000) - /usr/lib64/libc-2.17.so
(00007f84ea21f000-00007f84ea223000) - /readhook/dll/basehook.so
Search region: (00007f84ea21f000-00007f84ea223000) - /readhook/dll/basehook.so
(00007f84ea223000-00007f84ea423000) - /readhook/dll/basehook.so
(00007f84ea423000-00007f84ea424000) - /readhook/dll/basehook.so
(00007f84ea424000-00007f84ea425000) - /readhook/dll/basehook.so
(00007f84ea425000-00007f84ea447000) - /usr/lib64/ld-2.17.so
Search region: (00007f84ea425000-00007f84ea447000) - /usr/lib64/ld-2.17.so
(00007f84ea63d000-00007f84ea641000) - /usr/lib64/ld-2.17.so
(00007f84ea643000-00007f84ea646000) - /usr/lib64/ld-2.17.so
(00007f84ea646000-00007f84ea647000) - /usr/lib64/ld-2.17.so
(00007f84ea647000-00007f84ea648000) - /usr/lib64/ld-2.17.so
(00007f84ea648000-00007f84ea649000) - /usr/lib64/ld-2.17.so
(00007fff95017000-00007fff95038000) - [stack]
(00007fff950d5000-00007fff950d8000) - [vvar]
(00007fff950d8000-00007fff950da000) - [vdso]
Search region: (00007fff950d8000-00007fff950da000) - [vdso]
(ffffffffff600000-ffffffffff601000) - [vsyscall]
#endif

#if 0 // ubuntu:trusty
(000055b869c86000-000055b869c8b000) - /readhook/app/fullhook
Search region: (000055b869c86000-000055b869c8b000) - /readhook/app/fullhook
(000055b869e8a000-000055b869e8b000) - /readhook/app/fullhook
(000055b869e8b000-000055b869e8c000) - /readhook/app/fullhook
(000055b86a2fe000-000055b86a31f000) - [heap]
(00007f03ba3cb000-00007f03ba3ce000) - /lib/x86_64-linux-gnu/libdl-2.19.so
Search region: (00007f03ba3cb000-00007f03ba3ce000) - /lib/x86_64-linux-gnu/libdl-2.19.so
(00007f03ba3ce000-00007f03ba5cd000) - /lib/x86_64-linux-gnu/libdl-2.19.so
(00007f03ba5cd000-00007f03ba5ce000) - /lib/x86_64-linux-gnu/libdl-2.19.so
(00007f03ba5ce000-00007f03ba5cf000) - /lib/x86_64-linux-gnu/libdl-2.19.so
(00007f03ba5cf000-00007f03ba78d000) - /lib/x86_64-linux-gnu/libc-2.19.so
Search region: (00007f03ba5cf000-00007f03ba78d000) - /lib/x86_64-linux-gnu/libc-2.19.so
(00007f03ba78d000-00007f03ba98d000) - /lib/x86_64-linux-gnu/libc-2.19.so
(00007f03ba98d000-00007f03ba991000) - /lib/x86_64-linux-gnu/libc-2.19.so
(00007f03ba991000-00007f03ba993000) - /lib/x86_64-linux-gnu/libc-2.19.so
(00007f03ba993000-00007f03ba998000) - /lib/x86_64-linux-gnu/libc-2.19.so
(00007f03ba998000-00007f03ba99c000) - /readhook/dll/basehook.so
Search region: (00007f03ba998000-00007f03ba99c000) - /readhook/dll/basehook.so
(00007f03ba99c000-00007f03bab9c000) - /readhook/dll/basehook.so
(00007f03bab9c000-00007f03bab9d000) - /readhook/dll/basehook.so
(00007f03bab9d000-00007f03bab9e000) - /readhook/dll/basehook.so
(00007f03bab9e000-00007f03babc1000) - /lib/x86_64-linux-gnu/ld-2.19.so
Search region: (00007f03bab9e000-00007f03babc1000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007f03badb8000-00007f03badbb000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007f03badbd000-00007f03badc0000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007f03badc0000-00007f03badc1000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007f03badc1000-00007f03badc2000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007f03badc2000-00007f03badc3000) - /lib/x86_64-linux-gnu/ld-2.19.so
(00007ffeab5b9000-00007ffeab5da000) - [stack]
(00007ffeab5f7000-00007ffeab5fa000) - [vvar]
(00007ffeab5fa000-00007ffeab5fc000) - [vdso]
Search region: (00007ffeab5fa000-00007ffeab5fc000) - [vdso]
(ffffffffff600000-ffffffffff601000) - [vsyscall]
#endif

#if 0 //ubuntu:bionic
(0000558cd21ad000-0000558cd21b2000) - /readhook/app/fullhook
Search region: (0000558cd21ad000-0000558cd21b2000) - /readhook/app/fullhook
(0000558cd23b1000-0000558cd23b2000) - /readhook/app/fullhook
(0000558cd23b2000-0000558cd23b3000) - /readhook/app/fullhook
(0000558cd3656000-0000558cd3677000) - [heap]
(00007fa24513d000-00007fa245140000) - /lib/x86_64-linux-gnu/libdl-2.27.so
Search region: (00007fa24513d000-00007fa245140000) - /lib/x86_64-linux-gnu/libdl-2.27.so
(00007fa245140000-00007fa24533f000) - /lib/x86_64-linux-gnu/libdl-2.27.so
(00007fa24533f000-00007fa245340000) - /lib/x86_64-linux-gnu/libdl-2.27.so
(00007fa245340000-00007fa245341000) - /lib/x86_64-linux-gnu/libdl-2.27.so
(00007fa245341000-00007fa245528000) - /lib/x86_64-linux-gnu/libc-2.27.so
Search region: (00007fa245341000-00007fa245528000) - /lib/x86_64-linux-gnu/libc-2.27.so
(00007fa245528000-00007fa245728000) - /lib/x86_64-linux-gnu/libc-2.27.so
(00007fa245728000-00007fa24572c000) - /lib/x86_64-linux-gnu/libc-2.27.so
(00007fa24572c000-00007fa24572e000) - /lib/x86_64-linux-gnu/libc-2.27.so
(00007fa24572e000-00007fa245732000) - /lib/x86_64-linux-gnu/libc-2.27.so
(00007fa245732000-00007fa245736000) - /readhook/dll/basehook.so
Search region: (00007fa245732000-00007fa245736000) - /readhook/dll/basehook.so
(00007fa245736000-00007fa245936000) - /readhook/dll/basehook.so
(00007fa245936000-00007fa245937000) - /readhook/dll/basehook.so
(00007fa245937000-00007fa245938000) - /readhook/dll/basehook.so
(00007fa245938000-00007fa24595f000) - /lib/x86_64-linux-gnu/ld-2.27.so
Search region: (00007fa245938000-00007fa24595f000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007fa245b56000-00007fa245b59000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007fa245b5d000-00007fa245b5f000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007fa245b5f000-00007fa245b60000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007fa245b60000-00007fa245b61000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007fa245b61000-00007fa245b62000) - /lib/x86_64-linux-gnu/ld-2.27.so
(00007ffe77fb1000-00007ffe77fd2000) - [stack]
(00007ffe77fe0000-00007ffe77fe3000) - [vvar]
(00007ffe77fe3000-00007ffe77fe5000) - [vdso]
Search region: (00007ffe77fe3000-00007ffe77fe5000) - [vdso]
(ffffffffff600000-ffffffffff601000) - [vsyscall]
#endif

#if 0
(0000560926dcc000-0000560926ded000) - [heap]
(00007fa522bcd000-00007fa522d90000) - /usr/lib64/libc-2.17.so
(00007fa522f9b000-00007fa522f9f000) - /readhook/dll/basehook.so
(00007fffa6d9b000-00007fffa6dbc000) - [stack]
(00007fffa6de6000-00007fffa6de9000) - [vvar]
(00007fffa6de9000-00007fffa6deb000) - [vdso]
(ffffffffff600000-ffffffffff601000) - [vsyscall]
#endif

#endif
