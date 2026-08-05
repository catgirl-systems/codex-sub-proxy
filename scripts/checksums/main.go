package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const releaseSentinelName = ".csp-release-sentinel"

func main() {
	rootArg := flag.String("root", "", "directory to scan")
	outputArg := flag.String("output", "", "checksum file")
	flag.Parse()
	if *rootArg == "" || *outputArg == "" {
		fail("root and output are required")
	}
	root, err := cleanAbsolutePath(*rootArg)
	if err != nil {
		fail(err.Error())
	}
	output, err := cleanAbsolutePath(*outputArg)
	if err != nil {
		fail(err.Error())
	}
	if err := validatePathAncestors(root); err != nil {
		fail(err.Error())
	}
	if err := validatePathAncestors(filepath.Dir(output)); err != nil {
		fail(err.Error())
	}
	if info, err := os.Lstat(output); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			fail("checksum output is a symlink")
		}
		fail("checksum output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		fail(err.Error())
	}
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || path == output {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("checksum root contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("checksum root contains non-regular entry %q", path)
		}
		if filepath.Base(path) == releaseSentinelName {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !checksumHasSingleLink(info) {
			return fmt.Errorf("checksum entry has multiple links %q", path)
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		fail(err.Error())
	}
	sort.Strings(paths)
	parent := filepath.Dir(output)
	temporary, err := os.OpenFile(filepath.Join(parent, ".checksums-"+filepath.Base(output)+".tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(err.Error())
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	for _, path := range paths {
		digest, err := hash(path)
		if err != nil {
			fail(err.Error())
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			fail(err.Error())
		}
		if _, err := fmt.Fprintf(temporary, "%s  %s\n", hex.EncodeToString(digest[:]), filepath.ToSlash(relative)); err != nil {
			fail(err.Error())
		}
	}
	if err := temporary.Sync(); err != nil {
		fail(err.Error())
	}
	if err := temporary.Close(); err != nil {
		fail(err.Error())
	}
	if _, err := os.Lstat(output); err == nil {
		fail("checksum output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		fail(err.Error())
	}
	if err := os.Link(temporaryPath, output); err != nil {
		fail(err.Error())
	}
	removeTemporary = false
	if err := os.Remove(temporaryPath); err != nil {
		fail(err.Error())
	}
	if err := syncDirectory(parent); err != nil {
		fail(err.Error())
	}
}
func cleanAbsolutePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for _, prefix := range []string{"/tmp", "/var"} {
		if absolute == prefix || strings.HasPrefix(absolute, prefix+string(filepath.Separator)) {
			resolved, err := filepath.EvalSymlinks(prefix)
			if err != nil {
				return "", err
			}
			absolute = resolved + strings.TrimPrefix(absolute, prefix)
			break
		}
	}
	if filepath.Clean(absolute) != absolute || absolute == string(filepath.Separator) {
		return "", errors.New("path is unsafe")
	}
	return absolute, nil
}

func validatePathAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("path ancestor %q is a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("path ancestor %q is not a directory", current)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func hash(path string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return digest, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !checksumHasSingleLink(info) {
		if err != nil {
			return digest, err
		}
		return digest, errors.New("checksum source is not a private regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return digest, err
	}
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func checksumHasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	return directory.Sync()
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
