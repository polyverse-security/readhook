CC=gcc
CFLAGS=-g -std=gnu99 -fstack-protector-all -fPIC

applications=app/fullhook
libraries=lib/utilhook.a
dlls=dll/basehook.so dll/fullhook.so dll/noophook.so dll/nullhook.so

all=$(applications) $(dlls)

all: $(all)

.PHONY: clean
clean:
	rm -f $(all) app/* dll/* lib/* obj/*

obj/addresses.o: src/addresses.c

obj/base64.o: src/base64.c

obj/memory.o: src/memory.c

obj/payload.o: src/payload.c

obj/shellcode.o: src/shellcode.c

obj/strlcpy.o: src/strlcpy.c

obj/strnstr.o: src/strnstr.c

obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

lib/utilhook.a: obj/addresses.o obj/base64.o obj/memory.o obj/payload.o obj/shellcode.o obj/strlcpy.o obj/strnstr.o
	$(AR) cvq $@ $^

dll/basehook.so: src/basehook.c src/fallback.c lib/utilhook.a
	$(CC) $(CFLAGS) -Fpie -pie src/basehook.c src/fallback.c -Wl,-z,relro,-z,now,-soname,basehook.so -shared -lc -ldl lib/utilhook.a -o dll/basehook.so

dll/fullhook.so: src/fullhook.c lib/utilhook.a dll/basehook.so
	$(CC) $(CFLAGS) -Fpie -pie src/fullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a dll/basehook.so -o dll/fullhook.so

dll/noophook.so: src/noophook.c lib/utilhook.a
	$(CC) $(CFLAGS) -Fpie -pie src/noophook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/noophook.so

dll/nullhook.so: src/nullhook.c lib/utilhook.a
	$(CC) $(CFLAGS) -Fpie -pie src/nullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/nullhook.so

app/fullhook: src/fullhook.c lib/utilhook.a dll/basehook.so
	$(CC) $(CFLAGS) -Fpie -pie -DFULLHOOK_MAIN=1 src/fullhook.c lib/utilhook.a dll/basehook.so -Wl,-z,relro,-z,now -lc -ldl -o app/fullhook

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

