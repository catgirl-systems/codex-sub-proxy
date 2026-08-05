package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	epoch := flag.Int64("epoch", -1, "file timestamp")
	flag.Parse()
	if *epoch < 0 || flag.NArg() == 0 {
		fail("epoch and at least one file are required")
	}
	stamp := time.Unix(*epoch, 0).UTC()
	for _, path := range flag.Args() {
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			fail(fmt.Sprintf("set mtime %q: %v", path, err))
		}
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
