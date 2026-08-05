package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	epoch := flag.Int64("epoch", -1, "timestamp")
	flag.Parse()
	if *epoch < 0 {
		fmt.Fprintln(os.Stderr, "epoch is required")
		os.Exit(1)
	}
	fmt.Print(time.Unix(*epoch, 0).UTC().Format(time.RFC3339))
}
