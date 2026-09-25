#!/bin/sh
# cli_test.sh - command-line behaviour: exit codes, output, CSV file.
#
#   sh tests/cli_test.sh ./build/pcapstat build
#
# Uses the committed sample capture (samples/sample.pcap).

BIN=${1:?usage: cli_test.sh PCAPSTAT_BINARY TMPDIR}
TMP=${2:-.}
SAMPLE=samples/sample.pcap
pass=0
fail=0

# expect_exit CODE DESCRIPTION -- COMMAND...
expect_exit() {
    want=$1
    what=$2
    shift 3
    "$@" >"$TMP/cli_out.txt" 2>"$TMP/cli_err.txt"
    got=$?
    if [ "$got" -eq "$want" ]; then
        pass=$((pass + 1))
        echo "ok    cli: $what"
    else
        fail=$((fail + 1))
        echo "FAIL  cli: $what (exit $got, want $want)"
        cat "$TMP/cli_err.txt"
    fi
}

# expect_grep PATTERN FILE DESCRIPTION
expect_grep() {
    if grep -q -- "$1" "$2"; then
        pass=$((pass + 1))
        echo "ok    cli: $3"
    else
        fail=$((fail + 1))
        echo "FAIL  cli: $3 (no '$1' in $2)"
    fi
}

expect_exit 0 "--help exits 0" -- "$BIN" --help
expect_grep "usage: pcapstat" "$TMP/cli_out.txt" "--help prints usage"
expect_exit 1 "no arguments is a usage error" -- "$BIN"
expect_exit 1 "unknown option" -- "$BIN" --bogus "$SAMPLE"
expect_exit 1 "-n without a value" -- "$BIN" "$SAMPLE" -n
expect_exit 1 "-n with a negative value" -- "$BIN" -n -1 "$SAMPLE"
expect_exit 1 "-n with trailing junk" -- "$BIN" -n 5x "$SAMPLE"
expect_exit 1 "two input files" -- "$BIN" "$SAMPLE" "$SAMPLE"
expect_exit 2 "missing file is an input error" -- "$BIN" "$TMP/does-not-exist.pcap"
expect_grep "cannot open file" "$TMP/cli_err.txt" "missing file message"

printf 'this is not a capture file\n' >"$TMP/cli_not_pcap.txt"
expect_exit 2 "non-pcap file" -- "$BIN" "$TMP/cli_not_pcap.txt"
expect_grep "not a pcap file" "$TMP/cli_err.txt" "non-pcap message"

# The sample cut short in the middle of a record: partial stats, exit 2.
size=$(wc -c <"$SAMPLE")
head -c $((size - 7)) "$SAMPLE" >"$TMP/cli_truncated.pcap"
expect_exit 2 "truncated capture" -- "$BIN" "$TMP/cli_truncated.pcap"
expect_grep "truncated file" "$TMP/cli_err.txt" "truncation reported on stderr"
expect_grep "^Packets:" "$TMP/cli_out.txt" "partial statistics still printed"

expect_exit 0 "sample capture" -- "$BIN" -n 3 --csv "$TMP/cli_flows.csv" "$SAMPLE"
expect_grep "^Top 3 of" "$TMP/cli_out.txt" "top-N table printed"
expect_grep "^src_addr,src_port,dst_addr,dst_port,protocol,ip_version,packets,bytes,first_ts,last_ts,duration_s,tcp_flags$" \
    "$TMP/cli_flows.csv" "CSV header row"

# One CSV row per flow: rows = the "Flows:" count from the summary.
flows=$(sed -n 's/^Flows: *//p' "$TMP/cli_out.txt")
rows=$(($(wc -l <"$TMP/cli_flows.csv") - 1))
if [ "$flows" = "$rows" ]; then
    pass=$((pass + 1))
    echo "ok    cli: CSV has one row per flow ($rows)"
else
    fail=$((fail + 1))
    echo "FAIL  cli: CSV rows $rows != flows $flows"
fi

expect_exit 0 "-n 0 hides the table" -- "$BIN" -n 0 "$SAMPLE"
if grep -q "^Top " "$TMP/cli_out.txt"; then
    fail=$((fail + 1))
    echo "FAIL  cli: table printed with -n 0"
else
    pass=$((pass + 1))
    echo "ok    cli: no table with -n 0"
fi

expect_exit 2 "unwritable CSV path" -- "$BIN" --csv "$TMP/no-such-dir/x.csv" "$SAMPLE"

# --csv naming the input file must be refused before anything is written.
# Run on a copy so a regression cannot damage the committed sample.
cp "$SAMPLE" "$TMP/cli_copy.pcap"
expect_exit 1 "--csv same as the input file" -- \
    "$BIN" --csv "$TMP/cli_copy.pcap" "$TMP/cli_copy.pcap"
if cmp -s "$SAMPLE" "$TMP/cli_copy.pcap"; then
    pass=$((pass + 1))
    echo "ok    cli: input file left untouched"
else
    fail=$((fail + 1))
    echo "FAIL  cli: input file was modified"
fi

rm -f "$TMP"/cli_out.txt "$TMP"/cli_err.txt "$TMP"/cli_not_pcap.txt \
    "$TMP"/cli_truncated.pcap "$TMP"/cli_flows.csv "$TMP"/cli_copy.pcap
echo
echo "$pass cli checks passed, $fail failed"
[ "$fail" -eq 0 ]
