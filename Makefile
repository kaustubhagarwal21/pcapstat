# pcapstat - build and benchmark.
#
#   make            release build: build/pcapstat
#   make bench      generate a 1,000,000-packet capture (if missing) and time it
#   make clean

CC      ?= cc
PYTHON  ?= python3
BUILD   := build

WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Werror
CFLAGS  ?= -std=c11 -O2 $(WARN)

LIB_SRC := src/pcap_reader.c src/decode.c src/flow.c src/stats.c \
           src/addr.c src/report.c src/analyze.c
HEADERS := $(wildcard src/*.h)

BENCH_PCAP    ?= bench/bench_1m.pcap
BENCH_PACKETS ?= 1000000
BENCH_FLOWS   ?= 20000

.PHONY: all bench sample clean

all: $(BUILD)/pcapstat

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/pcapstat: $(LIB_SRC) src/main.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(LIB_SRC) src/main.c

$(BENCH_PCAP):
	@mkdir -p $(dir $@)
	$(PYTHON) tools/gen_pcap.py --seed 1 --packets $(BENCH_PACKETS) \
	    --flows $(BENCH_FLOWS) --out $@

bench: $(BUILD)/pcapstat $(BENCH_PCAP)
	@ls -l $(BENCH_PCAP)
	@echo "timing: ./$(BUILD)/pcapstat -n 5 $(BENCH_PCAP)"
	@bash -c 'time ./$(BUILD)/pcapstat -n 5 $(BENCH_PCAP) > /dev/null'

# Regenerate the small committed sample capture. Seed 17 was picked because
# its 400 packets include every protocol path (ICMP, ICMPv6, IPv4 fragments,
# VLAN tags, non-IP frames) alongside TCP and UDP.
sample:
	$(PYTHON) tools/gen_pcap.py --seed 17 --packets 400 --flows 30 \
	    --out samples/sample.pcap

clean:
	rm -rf $(BUILD)
