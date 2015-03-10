CC     := gcc
LD     := gcc

CFLAGS += -std=c99 -D_LARGEFILE64_SOURCE

ifeq ($(DEBUG),)
CFLAGS += -DNDEBUG -O2
else
CFLAGS += -g
endif

ntfsclone2vhd: ntfsclone2vhd.o
	$(LD) -o $@ $<

clean:
	rm -f ntfsclone2vhd.o ntfsclone2vhd
