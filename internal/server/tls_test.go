package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
)

func TestTLSListenersServeHTTPSAndRejectPlaintext(t *testing.T) {
	certificate, privateKey := testCertificate(t)
	certificatePath := filepath.Join(t.TempDir(), "server.crt")
	privateKeyPath := filepath.Join(filepath.Dir(certificatePath), "server.key")
	if err := os.WriteFile(certificatePath, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.AdminListen = "127.0.0.1:0"
	cfg.Server.DataTLS = config.TLSConfig{CertificateFile: certificatePath, PrivateKeyFile: privateKeyPath}
	cfg.Server.AdminTLS = cfg.Server.DataTLS
	servers, err := Start(Config{
		Listen:               cfg.Server.Listen,
		AdminListen:          cfg.Server.AdminListen,
		AdminCookieSecure:    true,
		CORS:                 cfg.CORS,
		DataTLS:              cfg.Server.DataTLS,
		AdminTLS:             cfg.Server.AdminTLS,
		JournalMode:          string(cfg.Journal.Mode),
		JournalQueueCapacity: cfg.Journal.QueueCapacity,
		JournalDrainDeadline: cfg.Journal.DrainDeadline,
		Retention: RetentionConfig{
			PayloadTTL: cfg.Retention.PayloadTTL, MetadataTTL: cfg.Retention.MetadataTTL,
			SweepInterval: cfg.Retention.SweepInterval, BatchSize: cfg.Retention.BatchSize,
			DrainDeadline: cfg.Retention.DrainDeadline,
		},
	}, NewReadiness())
	if err != nil {
		t.Fatalf("start TLS listeners: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer servers.Shutdown(ctx)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Get("https://" + servers.DataAddr() + "/healthz")
	if err != nil {
		t.Fatalf("HTTPS health request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS health status = %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	plainClient := &http.Client{Timeout: time.Second}
	plainResponse, err := plainClient.Get("http://" + servers.DataAddr() + "/healthz")
	if err == nil {
		defer plainResponse.Body.Close()
		if plainResponse.StatusCode < http.StatusBadRequest {
			t.Fatalf("plaintext request unexpectedly succeeded with status %d", plainResponse.StatusCode)
		}
	}
}

func testCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	serial := new(big.Int).SetInt64(1)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return certificate, privateKey
}
