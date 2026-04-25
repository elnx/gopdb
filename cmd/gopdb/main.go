package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/elnx/gopdb"
	"github.com/elnx/gopdb/symdl"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <file> <base_address>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nAccepts PDB or PE files. PE files trigger automatic PDB download.\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	filename := flag.Arg(0)
	baseStr := flag.Arg(1)

	baseAddress, err := strconv.ParseUint(baseStr, 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid base address %q: %v\n", baseStr, err)
		os.Exit(1)
	}

	var pdb *gopdb.PDB
	if symdl.IsPE(filename) {
		fmt.Fprintf(os.Stderr, "[>] Input is a PE file, downloading PDB...\n")
		pdb, err = gopdb.OpenPE(filename)
	} else {
		pdb, err = gopdb.OpenPDB(filename)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer pdb.Close()

	sects := pdb.ActiveSections()

	for _, sym := range pdb.Symbols {
		segIdx := int(sym.Segment) - 1
		if segIdx < 0 || segIdx >= len(sects) {
			fmt.Fprintf(os.Stderr, "Skipping %s, segment %d does not exist\n", sym.Name, sym.Segment-1)
			continue
		}

		virtBase := sects[segIdx].VirtualAddress
		rva := baseAddress + uint64(pdb.Remap(sym.Offset+virtBase))
		fmt.Printf("%s,%#x,%d,%s\n", sym.Name, rva, sym.SymType, sects[segIdx].Name)
	}
}
