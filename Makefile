.PHONY: build build-all test bench clean

GOPDB_TEST_FILE ?=

build:
	go build -o gopdb ./cmd/gopdb

build-all:
	go build -o gopdb ./cmd/gopdb
	go build -o symchk ./cmd/symchk

test:
	GOPDB_TEST_FILE=$(GOPDB_TEST_FILE) go test -v ./...

bench:
	GOPDB_TEST_FILE=$(GOPDB_TEST_FILE) go test -bench=. -benchmem ./...

clean:
	rm -f gopdb symchk
