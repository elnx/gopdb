.PHONY: build test bench clean

GOPDB_TEST_FILE ?=

build:
	go build -o gopdb ./cmd/gopdb

test:
	GOPDB_TEST_FILE=$(GOPDB_TEST_FILE) go test -v ./...

bench:
	GOPDB_TEST_FILE=$(GOPDB_TEST_FILE) go test -bench=. -benchmem ./...

clean:
	rm -f gopdb
