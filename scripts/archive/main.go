package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	root := flag.String("root", "", "directory to archive")
	output := flag.String("output", "", "archive path")
	name := flag.String("name", "", "archive root name")
	epoch := flag.Int64("epoch", -1, "archive timestamp")
	flag.Parse()
	if *root == "" || *output == "" || *name == "" || *epoch < 0 {
		fail("root, output, name, and epoch are required")
	}
	info, err := os.Stat(*root)
	if err != nil || !info.IsDir() {
		fail("archive root is not a directory")
	}
	entries := make([]string, 0)
	if err := filepath.WalkDir(*root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == *root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive root contains symlink %q", path)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("archive root contains non-regular entry %q", path)
		}
		entries = append(entries, path)
		return nil
	}); err != nil {
		fail(err.Error())
	}
	sort.Strings(entries)
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		fail(err.Error())
	}
	temporary, err := os.CreateTemp(filepath.Dir(*output), ".archive-*")
	if err != nil {
		fail(err.Error())
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		fail(err.Error())
	}
	writer := tar.NewWriter(temporary)
	stamp := time.Unix(*epoch, 0).UTC()
	for _, path := range entries {
		fileInfo, err := os.Stat(path)
		if err != nil {
			_ = writer.Close()
			_ = temporary.Close()
			fail(err.Error())
		}
		relative, err := filepath.Rel(*root, path)
		if err != nil {
			_ = writer.Close()
			_ = temporary.Close()
			fail(err.Error())
		}
		tarName := filepath.ToSlash(filepath.Join(*name, relative))
		if strings.HasPrefix(tarName, "../") || tarName == ".." {
			_ = writer.Close()
			_ = temporary.Close()
			fail("archive path escapes root")
		}
		header := &tar.Header{Name: tarName, Mode: int64(fileInfo.Mode().Perm()), Size: fileInfo.Size(), ModTime: stamp, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			_ = writer.Close()
			_ = temporary.Close()
			fail(err.Error())
		}
		file, err := os.Open(path)
		if err != nil {
			_ = writer.Close()
			_ = temporary.Close()
			fail(err.Error())
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			_ = writer.Close()
			_ = temporary.Close()
			if copyErr != nil {
				fail(copyErr.Error())
			}
			fail(closeErr.Error())
		}
	}
	if err := writer.Close(); err != nil {
		_ = temporary.Close()
		fail(err.Error())
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		fail(err.Error())
	}
	if err := temporary.Close(); err != nil {
		fail(err.Error())
	}
	if err := os.Rename(temporaryPath, *output); err != nil {
		fail(err.Error())
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
