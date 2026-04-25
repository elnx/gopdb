package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/elnx/gopdb/symdl"
)

func main() {
	var recurse bool
	var verbose bool
	var threads int
	var outputDir string

	flag.BoolVar(&recurse, "r", false, "recurse into directories")
	flag.BoolVar(&verbose, "v", false, "print verbose details")
	flag.IntVar(&threads, "t", 1, "number of concurrent workers when using -r")
	flag.StringVar(&outputDir, "o", "", "symbol cache directory (overrides NT_SYMBOL_PATH local cache)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-r] [-v] [-t n] [-o dir] <file-or-directory>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if threads < 1 {
		fmt.Fprintf(os.Stderr, "config error: -t must be at least 1\n")
		os.Exit(1)
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := symdl.LoadConfig(outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	files, err := symdl.CollectTargets(flag.Arg(0), recurse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "target error: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no PE files found\n")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tempFiles, err := symdl.NewTempFileManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp file manager error: %v\n", err)
		os.Exit(1)
	}
	if err := tempFiles.CleanupStale(cfg.CacheDir); err != nil {
		fmt.Fprintf(os.Stderr, "temp file cleanup error: %v\n", err)
		os.Exit(1)
	}

	runner := symdl.Checker{
		Ctx:       ctx,
		Config:    cfg,
		Client:    &http.Client{Timeout: 30 * time.Second},
		Verbose:   verbose,
		TempFiles: tempFiles,
	}

	parallelism := 1
	if recurse {
		parallelism = threads
	}

	results, summary := symdl.RunChecks(runner, files, parallelism)
	for _, result := range results {
		printResult(os.Stdout, result, verbose)
	}
	printSummary(os.Stdout, summary)

	if summary.Failures > 0 {
		os.Exit(1)
	}
}

func printResult(w io.Writer, result symdl.Result, verbose bool) {
	fmt.Fprintf(w, "%s: %s", result.Path, result.Status)
	if result.Message != "" {
		fmt.Fprintf(w, " (%s)", result.Message)
	}
	fmt.Fprintln(w)
	if !verbose {
		return
	}
	if result.PDBName != "" {
		fmt.Fprintf(w, "  pdb: %s\n", result.PDBName)
	}
	if result.GUIDAge != "" {
		fmt.Fprintf(w, "  guidage: %s\n", result.GUIDAge)
	}
	if result.CachePath != "" {
		fmt.Fprintf(w, "  cache: %s\n", result.CachePath)
	}
	if result.URL != "" {
		fmt.Fprintf(w, "  url: %s\n", result.URL)
	}
}

func printSummary(w io.Writer, summary symdl.Summary) {
	fmt.Fprintf(w, "summary: processed=%d cached=%d downloaded=%d missing=%d failures=%d\n",
		summary.Processed,
		summary.Cached,
		summary.Downloaded,
		summary.Missing,
		summary.Failures,
	)
}
