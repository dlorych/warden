// devinit creates development-only trust material. It is deliberately a
// separate command so production deployments never need the generated user
// private keys.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wardenv/service/pkg/evidence"
)

const (
	requester = "11111111-1111-4111-8111-111111111111"
	reviewer  = "22222222-2222-4222-8222-222222222222"
)

type config struct {
	CAFile               string `json:"ca_file"`
	CheckpointPublicKey  string `json:"checkpoint_public_key"`
	CheckpointOrigin     string `json:"checkpoint_origin"`
	RequesterCertificate string `json:"requester_certificate"`
	ReviewerCertificate  string `json:"reviewer_certificate"`
	// User private key paths are intentionally only in the local developer
	// config, never in service configuration or a container mount.
	RequesterKey string `json:"requester_key"`
	ReviewerKey  string `json:"reviewer_key"`
}

func main() {
	dir := flag.String("dir", ".dev", "development material directory")
	force := flag.Bool("force", false, "replace existing development material")
	flag.Parse()
	if err := run(*dir, *force); err != nil {
		fmt.Fprintln(os.Stderr, "devinit:", err)
		os.Exit(1)
	}
}

func run(dir string, force bool) error {
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return fmt.Errorf("refusing unsafe development directory %q", dir)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if !force {
		if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err == nil {
			for _, name := range []string{"ca-key.pem", "requester.pem", "requester-key.pem", "reviewer.pem", "reviewer-key.pem", "app-key.pem", "rekor-signer.key", "rekor-public.pem", "trust.json"} {
				if _, e := os.Stat(filepath.Join(dir, name)); e != nil {
					return fmt.Errorf("development material is incomplete (%s); use --force to replace", name)
				}
			}
			fmt.Printf("development trust material already exists in %s\n", dir)
			return nil
		}
	}
	now := time.Now().UTC()
	cak, cac, capem, cakeypem, err := evidence.NewDevCA(now)
	if err != nil {
		return err
	}
	_, _, reqCert, reqKey, err := evidence.NewDevCertificate(now, cac, cak, requester)
	if err != nil {
		return err
	}
	_, _, revCert, revKey, err := evidence.NewDevCertificate(now, cac, cak, reviewer)
	if err != nil {
		return err
	}
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	appDER := x509.MarshalPKCS1PrivateKey(appKey)
	appPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: appDER})
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signerDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return err
	}
	signerPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signerDER})
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	files := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"ca.pem": {capem, 0644}, "ca-key.pem": {cakeypem, 0600},
		"requester.pem": {reqCert, 0644}, "requester-key.pem": {reqKey, 0600}, "reviewer.pem": {revCert, 0644}, "reviewer-key.pem": {revKey, 0600},
		"app-key.pem": {appPEM, 0600}, "rekor-signer.key": {signerPEM, 0600}, "rekor-public.pem": {pubPEM, 0644},
	}
	for name, f := range files {
		if err := writeFile(filepath.Join(dir, name), f.data, f.mode, force); err != nil {
			return err
		}
	}
	trusted := config{CAFile: "ca.pem", CheckpointPublicKey: base64.StdEncoding.EncodeToString(pub), CheckpointOrigin: "rekor-local", RequesterCertificate: "requester.pem", ReviewerCertificate: "reviewer.pem", RequesterKey: "requester-key.pem", ReviewerKey: "reviewer-key.pem"}
	cb, _ := json.MarshalIndent(trusted, "", "  ")
	cb = append(cb, '\n')
	if err := writeFile(filepath.Join(dir, "trust.json"), cb, 0644, force); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, ".gitignore"), []byte("*\n!.gitignore\n"), 0644, force); err != nil {
		return err
	}
	fmt.Printf("created development trust material in %s\n", dir)
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Chmod(mode)
}
