package server

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
)

const maxTLSFileBytes = 1 << 20

func loadTLSConfig(settings config.TLSConfig) (*tls.Config, error) {
	certificatePath := strings.TrimSpace(settings.CertificateFile)
	keyPath := strings.TrimSpace(settings.PrivateKeyFile)
	if certificatePath == "" && keyPath == "" {
		return nil, nil
	}
	if certificatePath == "" || keyPath == "" {
		return nil, errors.New("TLS certificate and private key must be configured together")
	}
	certificate, err := readTLSFile(certificatePath, false)
	if err != nil {
		return nil, errors.New("read TLS certificate")
	}
	privateKey, err := readTLSFile(keyPath, true)
	if err != nil {
		return nil, errors.New("read TLS private key")
	}
	pair, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, errors.New("parse TLS certificate and private key")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func readTLSFile(path string, privateKey bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxTLSFileBytes {
		return nil, errors.New("TLS file is not a bounded regular file")
	}
	if privateKey && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("TLS private key permissions are too broad")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open TLS file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTLSFileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxTLSFileBytes {
		return nil, errors.New("read TLS file")
	}
	return data, nil
}
