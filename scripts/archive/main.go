package main

import (
	"archive/tar"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type archiveEntry struct {
	name string
	info os.FileInfo
}

func main() {
	rootArg := flag.String("root", "", "directory to archive")
	outputArg := flag.String("output", "", "archive path")
	name := flag.String("name", "", "archive root name")
	epoch := flag.Int64("epoch", -1, "archive timestamp")
	flag.Parse()
	if *rootArg == "" || *outputArg == "" || *name == "" || *epoch < 0 {
		fail("root, output, name, and epoch are required")
	}
	rootPath, err := cleanAbsolutePath(*rootArg)
	if err != nil {
		fail(fmt.Sprintf("archive root: %v", err))
	}
	outputPath, err := cleanAbsolutePath(*outputArg)
	if err != nil {
		fail(fmt.Sprintf("archive output: %v", err))
	}
	if err := validatePathAncestors(rootPath); err != nil {
		fail(fmt.Sprintf("archive root: %v", err))
	}
	if err := validatePathAncestors(filepath.Dir(outputPath)); err != nil {
		fail(fmt.Sprintf("archive output: %v", err))
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		fail("archive root is not a directory")
	}
	if err := validateOutputPath(outputPath); err != nil {
		fail(err.Error())
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		fail(fmt.Sprintf("open archive root: %v", err))
	}
	defer root.Close()
	entries, err := enumerateRoot(root, ".")
	if err != nil {
		fail(err.Error())
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	if err := writeArchive(root, entries, outputPath, *name, time.Unix(*epoch, 0).UTC()); err != nil {
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

func validateOutputPath(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("archive output is a symlink")
		}
		return errors.New("archive output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect archive output: %w", err)
	}
	return nil
}

func enumerateRoot(root *os.Root, directory string) ([]archiveEntry, error) {
	handle, err := root.Open(directory)
	if err != nil {
		return nil, fmt.Errorf("open archive directory %q: %w", directory, err)
	}
	entries, readErr := handle.ReadDir(-1)
	closeErr := handle.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read archive directory %q: %w", directory, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close archive directory %q: %w", directory, closeErr)
	}
	result := make([]archiveEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		relative := name
		if directory != "." {
			relative = filepath.Join(directory, name)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("archive root contains symlink %q", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect archive entry %q: %w", relative, err)
		}
		if info.IsDir() {
			nested, err := enumerateRoot(root, relative)
			if err != nil {
				return nil, err
			}
			result = append(result, nested...)
			continue
		}
		if !info.Mode().IsRegular() || !archiveHasSingleLink(info) {
			return nil, fmt.Errorf("archive root contains non-regular entry %q", relative)
		}
		result = append(result, archiveEntry{name: relative, info: info})
	}
	return result, nil
}

func writeArchive(root *os.Root, entries []archiveEntry, output, archiveName string, stamp time.Time) error {
	parent := filepath.Dir(output)
	temporary, err := os.OpenFile(filepath.Join(parent, ".archive-"+filepath.Base(output)+".tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create archive temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	writer := tar.NewWriter(temporary)
	for _, entry := range entries {
		file, info, err := openArchiveEntry(root, entry)
		if err != nil {
			_ = writer.Close()
			return err
		}
		tarName := filepath.ToSlash(filepath.Join(archiveName, entry.name))
		if strings.HasPrefix(tarName, "../") || tarName == ".." {
			_ = file.Close()
			_ = writer.Close()
			return errors.New("archive path escapes root")
		}
		header := &tar.Header{Name: tarName, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: stamp, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			_ = file.Close()
			_ = writer.Close()
			return fmt.Errorf("write archive header %q: %w", entry.name, err)
		}
		if err := copyExact(writer, file, info.Size()); err != nil {
			_ = file.Close()
			_ = writer.Close()
			return fmt.Errorf("copy archive entry %q: %w", entry.name, err)
		}
		closeErr := file.Close()
		if closeErr != nil {
			_ = writer.Close()
			return fmt.Errorf("close archive entry %q: %w", entry.name, closeErr)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close archive file: %w", err)
	}
	if err := validateOutputPath(output); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, output); err != nil {
		return fmt.Errorf("publish archive: %w", err)
	}
	removeTemporary = false
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("remove archive temporary file: %w", err)
	}
	return syncDirectory(parent)
}

func openArchiveEntry(root *os.Root, discovered archiveEntry) (*os.File, os.FileInfo, error) {
	file, err := root.OpenFile(discovered.name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open archive entry %q: %w", discovered.name, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat archive entry %q: %w", discovered.name, err)
	}
	if !info.Mode().IsRegular() || !archiveHasSingleLink(info) || !os.SameFile(discovered.info, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("archive entry %q changed during discovery", discovered.name)
	}
	return file, info, nil
}

func copyExact(destination io.Writer, source io.Reader, size int64) error {
	written, err := io.Copy(destination, io.LimitReader(source, size+1))
	if err != nil {
		return err
	}
	if written != size {
		return errors.New("archive entry size changed")
	}
	return nil
}

func archiveHasSingleLink(info os.FileInfo) bool {
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
