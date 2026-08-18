package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
)

var (
	ErrCorruptCapsule = errors.New("corrupt capsule container or failed hash validation")
	ErrPathTraversal  = errors.New("file path attempts directory traversal")
)

// Manifest contains metadata and verification instructions for a recovery capsule.
type Manifest struct {
	CapsuleID          string                 `json:"capsule_id"`
	ServiceName        string                 `json:"service_name"`
	AppVersion         string                 `json:"app_version"`
	CreatedAt          time.Time              `json:"created_at"`
	PayloadHash        string                 `json:"payload_hash"` // SHA-256 hex of tar.gz payload
	Threshold          int                    `json:"threshold"`
	TotalShares        int                    `json:"total_shares"`
	Dependencies       map[string]interface{} `json:"dependencies"`
	VerificationRecipe map[string]interface{} `json:"verification_recipe"`
}

// BackupFile represents an in-memory or on-disk file payload to include in a capsule.
type BackupFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode int64  `json:"mode"`
}

// Capsule represents an encapsulated and encrypted backup container.
type Capsule struct {
	Manifest   Manifest `json:"manifest"`
	Ciphertext []byte   `json:"ciphertext"` // AES-256-GCM encrypted tar.gz base64 string bytes
	Shares     []Share  `json:"shares"`     // Shamir shares of the ephemeral AES-256 key
}

// CreateCapsule bundles files, computes manifest, encrypts with ephemeral key, and splits key with Shamir.
func CreateCapsule(serviceName, appVersion string, files []BackupFile, deps, recipe map[string]interface{}, threshold, totalShares int) (*Capsule, []byte, error) {
	if threshold <= 0 {
		threshold = 2
	}
	if totalShares <= 0 {
		totalShares = 3
	}

	// 1. Pack files into compressed tar.gz
	var tarBuf bytes.Buffer
	gw := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gw)

	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0600
		}
		cleanPath := filepath.Clean(f.Path)
		if strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
			return nil, nil, fmt.Errorf("%w: %s", ErrPathTraversal, f.Path)
		}

		hdr := &tar.Header{
			Name:    cleanPath,
			Mode:    mode,
			Size:    int64(len(f.Data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, fmt.Errorf("failed to write tar header: %w", err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, nil, fmt.Errorf("failed to write tar data: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}

	tarBytes := tarBuf.Bytes()
	payloadHash := sha256.Sum256(tarBytes)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	capsuleID := fmt.Sprintf("cap-%s-%d", serviceName, time.Now().Unix())

	manifest := Manifest{
		CapsuleID:          capsuleID,
		ServiceName:        serviceName,
		AppVersion:         appVersion,
		CreatedAt:          time.Now().UTC(),
		PayloadHash:        payloadHashHex,
		Threshold:          threshold,
		TotalShares:        totalShares,
		Dependencies:       deps,
		VerificationRecipe: recipe,
	}

	// 2. Generate 32-byte ephemeral AES key and encrypt payload
	ephemeralKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, nil, err
	}

	ciphertextB64, err := crypto.EncryptAESGCM(ephemeralKey, tarBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt capsule payload: %w", err)
	}

	// 3. Split ephemeral key with Shamir's Secret Sharing
	shares, err := SplitSecret(ephemeralKey, threshold, totalShares)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split capsule key: %w", err)
	}

	capsule := &Capsule{
		Manifest:   manifest,
		Ciphertext: []byte(ciphertextB64),
		Shares:     shares,
	}

	return capsule, ephemeralKey, nil
}

// ExtractCapsule decapsulates, decrypts, and unpacks files into a target directory (with 0700 permissions).
func ExtractCapsule(capsule *Capsule, key []byte, targetDir string) ([]BackupFile, error) {
	// 1. Decrypt payload
	tarBytes, err := crypto.DecryptAESGCM(key, string(capsule.Ciphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}

	// 2. Verify payload hash integrity
	actualHash := sha256.Sum256(tarBytes)
	if hex.EncodeToString(actualHash[:]) != capsule.Manifest.PayloadHash {
		return nil, ErrCorruptCapsule
	}

	// 3. Unpack tar.gz
	gr, err := gzip.NewReader(bytes.NewReader(tarBytes))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var extractedFiles []BackupFile

	if targetDir != "" {
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			return nil, err
		}
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return nil, fmt.Errorf("%w: %s", ErrPathTraversal, hdr.Name)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}

		file := BackupFile{
			Path: cleanName,
			Data: data,
			Mode: hdr.Mode,
		}
		extractedFiles = append(extractedFiles, file)

		if targetDir != "" {
			destPath := filepath.Join(targetDir, cleanName)
			if !strings.HasPrefix(destPath, filepath.Clean(targetDir)) {
				return nil, fmt.Errorf("%w: %s", ErrPathTraversal, cleanName)
			}
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				return nil, err
			}
			mode := os.FileMode(hdr.Mode)
			if mode == 0 {
				mode = 0600
			}
			if err := os.WriteFile(destPath, data, mode); err != nil {
				return nil, err
			}
		}
	}

	return extractedFiles, nil
}
