package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	root := flag.String("root", "", "directory to scan")
	output := flag.String("output", "", "checksum file")
	flag.Parse()
	if *root == "" || *output == "" {
		fail("root and output are required")
	}
	var paths []string
	if err := filepath.Walk(*root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode().IsRegular() && path != *output {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		fail(err.Error())
	}
	sort.Strings(paths)
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		fail(err.Error())
	}
	for _, path := range paths {
		digest, err := hash(path)
		if err != nil {
			_ = file.Close()
			fail(err.Error())
		}
		relative, err := filepath.Rel(*root, path)
		if err != nil {
			_ = file.Close()
			fail(err.Error())
		}
		if _, err := fmt.Fprintf(file, "%s  %s\n", hex.EncodeToString(digest[:]), filepath.ToSlash(relative)); err != nil {
			_ = file.Close()
			fail(err.Error())
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		fail(err.Error())
	}
	if err := file.Close(); err != nil {
		fail(err.Error())
	}
}

func hash(path string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return digest, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return digest, err
	}
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
