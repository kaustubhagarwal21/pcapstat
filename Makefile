# pcapstat - build.
#
#   make            release build: build/pcapstat
#   make clean

CC      ?= cc
BUILD   := build

WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Werror
CFLAGS  ?= -std=c11 -O2 $(WARN)

LIB_SRC := src/pcap_reader.c src/decode.c
HEADERS := $(wildcard src/*.h)

.PHONY: all clean

all: $(BUILD)/pcapstat

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/pcapstat: $(LIB_SRC) src/main.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(LIB_SRC) src/main.c

clean:
	rm -rf $(BUILD)
