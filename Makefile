DESTDIR ?= /
PREFIX  ?= /usr
INCLUDE ?= -Ioffsetcache
all: jbctl

%.o: %.c
	$(CC) $(INCLUDE) -Wall -MMD -c $< -o $@

%.c.o: %.c
	$(CC) $(INCLUDE) -Wall -MMD -c $< -o $@

-include $(wildcard *.d)

jbctl: jbctl.c.o offsetcache/offsetcache.c.o
	$(CC) -O2 $^ -o $@

clean:
	rm -f jbctl *.o offsetcache/*.o *.d offsetcache/*.d

install: all
	mkdir -p $(DESTDIR)/$(PREFIX)/bin
	cp jbctl $(DESTDIR)/$(PREFIX)/bin
