package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const sentinelName = ".csp-release-sentinel"
const sentinelText = "codex-sub-proxy release output v1\n"

func main() {
	pathArg := flag.String("path", "", "release output directory")
	flag.Parse()
	if *pathArg == "" || flag.NArg() != 0 {
		fail("path is required")
	}
	path, err := cleanAbsolutePath(*pathArg)
	if err != nil {
		fail(err.Error())
	}
	if err := validateAncestors(path); err != nil {
		fail(err.Error())
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		fail(fmt.Sprintf("create release output parent: %v", err))
	}
	info, err := os.Lstat(path)
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		fail(fmt.Sprintf("inspect release output: %v", err))
	}
	if fresh {
		if err := os.Mkdir(path, 0o700); err != nil {
			fail(fmt.Sprintf("create release output: %v", err))
		}
		if err := writeSentinel(path); err != nil {
			fail(err.Error())
		}
	} else {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			fail("release output must be a private directory")
		}
		if err := validatePrivateDirectory(info); err != nil {
			fail(err.Error())
		}
		if err := validateSentinel(path); err != nil {
			fail(err.Error())
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			fail(fmt.Sprintf("open release output: %v", err))
		}
		if err := removeContents(root, "."); err != nil {
			_ = root.Close()
			fail(err.Error())
		}
		if err := root.Close(); err != nil {
			fail(fmt.Sprintf("close release output: %v", err))
		}
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
		return "", errors.New("release output path is unsafe")
	}
	return absolute, nil
}

func validateAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("release output ancestor %q is a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("release output ancestor %q is not a directory", current)
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

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return errors.New("release output is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Getuid()) {
		return errors.New("release output is not owned by the current user")
	}
	return nil
}

func writeSentinel(path string) error {
	file, err := os.OpenFile(filepath.Join(path, sentinelName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create release output sentinel: %w", err)
	}
	if _, err := io.WriteString(file, sentinelText); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateSentinel(path string) error {
	path = filepath.Join(path, sentinelName)
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("release output has no private script sentinel")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("release output sentinel is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || uint32(stat.Uid) != uint32(os.Getuid()) {
		return errors.New("release output sentinel ownership is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(sentinelText)+1)))
	if err != nil {
		return err
	}
	if string(data) != sentinelText {
		return errors.New("release output sentinel is invalid")
	}
	return nil
}

func removeContents(root *os.Root, directory string) error {
	handle, err := root.Open(directory)
	if err != nil {
		return err
	}
	entries, readErr := handle.ReadDir(-1)
	closeErr := handle.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		name := entry.Name()
		relative := name
		if directory != "." {
			relative = filepath.Join(directory, name)
		}
		if directory == "." && name == sentinelName {
			continue
		}
		if entry.Type()&os.ModeSymlink == 0 && entry.IsDir() {
			if err := removeContents(root, relative); err != nil {
				return fmt.Errorf("remove release output directory %q: %w", relative, err)
			}
		}
		if err := root.Remove(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove release output entry %q: %w", relative, err)
		}
	}
	return nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
