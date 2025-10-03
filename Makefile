CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g

all: libapp.so app libinj.so inject

libapp.so: app_lib.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

app: app.c libapp.so
	$(CC) $(CFLAGS) -o $@ $< -L. -lapp

libinj.so: inj_lib.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

inject: inject.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f libapp.so app libinj.so inject

.PHONY: all clean
