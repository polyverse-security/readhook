#FROM	alpine
#RUN	apk update
#RUN	apk add bash curl gcc libc-dev
#FROM	centos:7
#RUN	yum update -y
#RUN	yum install -y bash curl gcc libc6-dev
FROM	ubuntu:xenial
RUN	apt-get -y update
RUN	apt-get -y install bash curl gcc libc-dev

WORKDIR	/readhook
COPY	src src

ARG CFLAGS=-g

RUN	mkdir ./obj
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/addresses.o src/addresses.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/base64.o src/base64.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/memory.o src/memory.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/payload.o src/payload.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/shellcode.o src/shellcode.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/strlcpy.o src/strlcpy.c
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -c -o obj/strnstr.o src/strnstr.c

RUN	mkdir ./lib
RUN	ar -cvq lib/utilhook.a obj/*.o

RUN	mkdir ./dll
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/basehook.c src/fallback.c -Wl,-z,relro,-z,now,-soname,basehook.so -shared -lc -ldl lib/utilhook.a -o dll/basehook.so
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/fullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a dll/basehook.so -o dll/fullhook.so
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/noophook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/noophook.so
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/nullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/nullhook.so

RUN	mkdir ./app
RUN	gcc $CFLAGS -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie -DFULLHOOK_MAIN=1 src/fullhook.c lib/utilhook.a dll/basehook.so -Wl,-z,relro,-z,now -lc -ldl -o app/fullhook
