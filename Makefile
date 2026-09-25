# pcapstat - build, test, sanitize, fuzz, benchmark.
#
#   make            release build: build/pcapstat
#   make test       unit tests + CLI tests against the release build
#   make asan       unit + CLI tests under AddressSanitizer + UndefinedBehaviorSanitizer
#   make fuzz       mutation fuzzer under ASan/UBSan (FUZZ_ITERS iterations)
#   make bench      generate a 1,000,000-packet capture (if missing) and time it
#   make clean

CC      ?= cc
PYTHON  ?= python3
BUILD   := build

WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Werror
CFLAGS  ?= -std=c11 -O2 $(WARN)
# -fno-sanitize-recover makes the first UBSan report fatal, so a test or
# fuzz run cannot "pass" while printing undefined-behaviour warnings.
SANFLAGS := -std=c11 -O1 -g -fsanitize=address,undefined \
            -fno-sanitize-recover=all -fno-omit-frame-pointer $(WARN)

LIB_SRC := src/pcap_reader.c src/decode.c src/flow.c src/stats.c \
           src/addr.c src/report.c src/analyze.c
HEADERS := $(wildcard src/*.h)
TEST_SRC := tests/test_main.c tests/builder.c tests/test_pcap.c \
            tests/test_decode.c tests/test_flow.c tests/test_report.c
TEST_HDR := tests/test.h tests/builder.h

FUZZ_ITERS ?= 200000
FUZZ_SEED  ?= 1

BENCH_PCAP    ?= bench/bench_1m.pcap
BENCH_PACKETS ?= 1000000
BENCH_FLOWS   ?= 20000

.PHONY: all test asan fuzz bench sample clean

all: $(BUILD)/pcapstat

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/pcapstat: $(LIB_SRC) src/main.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(LIB_SRC) src/main.c

$(BUILD)/run_tests: $(LIB_SRC) $(TEST_SRC) $(HEADERS) $(TEST_HDR) | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ $(LIB_SRC) $(TEST_SRC)

$(BUILD)/run_tests_asan: $(LIB_SRC) $(TEST_SRC) $(HEADERS) $(TEST_HDR) | $(BUILD)
	$(CC) $(SANFLAGS) -Isrc -o $@ $(LIB_SRC) $(TEST_SRC)

$(BUILD)/pcapstat_asan: $(LIB_SRC) src/main.c $(HEADERS) | $(BUILD)
	$(CC) $(SANFLAGS) -o $@ $(LIB_SRC) src/main.c

$(BUILD)/fuzz_decode: fuzz/fuzz_decode.c tests/builder.c $(LIB_SRC) $(HEADERS) tests/builder.h | $(BUILD)
	$(CC) $(SANFLAGS) -Isrc -Itests -o $@ fuzz/fuzz_decode.c tests/builder.c $(LIB_SRC)

test: $(BUILD)/run_tests $(BUILD)/pcapstat
	./$(BUILD)/run_tests $(BUILD)
	sh tests/cli_test.sh ./$(BUILD)/pcapstat $(BUILD)

asan: $(BUILD)/run_tests_asan $(BUILD)/pcapstat_asan
	./$(BUILD)/run_tests_asan $(BUILD)
	sh tests/cli_test.sh ./$(BUILD)/pcapstat_asan $(BUILD)

fuzz: $(BUILD)/fuzz_decode
	./$(BUILD)/fuzz_decode $(FUZZ_ITERS) $(FUZZ_SEED)

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
