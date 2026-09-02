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
	"syscall"
	"time"

	"github.com/Busness-app/kysignon-server/internal/crypto"
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

// Extraction limits. A capsule is decrypted before it is unpacked, but "decrypts under a
// quorum" is not the same as "was produced by a healthy server": a custodian quorum that has
// been coerced, or a compromised host that built the capsule, can hand the restore tool a
// valid container whose payload expands to hundreds of gigabytes. These are variables rather
// than constants so tests can lower them.
var (
	maxCapsuleFiles         = 256
	maxCapsuleFileBytes     = int64(4 << 30) // 4 GiB for any single member
	maxCapsuleExpandedTotal = int64(8 << 30) // 8 GiB across the whole archive
)

var (
	ErrCapsuleTooLarge  = errors.New("capsule payload exceeds the permitted expanded size")
	ErrCapsuleEntryType = errors.New("capsule contains an entry that is not a regular file")
	ErrTargetNotEmpty   = errors.New("restore target directory is not empty")
)

// ExtractCapsule decapsulates, decrypts, and unpacks files into a target directory.
//
// When targetDir is set it must be empty or absent: the archive is written with O_NOFOLLOW
// and O_EXCL into a directory this function owns, so a pre-planted symlink beneath the
// target cannot redirect a restore onto a path outside it.
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

	// The gzip stream is the only place total expansion can be bounded once and for all;
	// per-entry caps alone still allow an unbounded number of entries.
	budget := &countingReader{r: io.LimitReader(gr, maxCapsuleExpandedTotal+1), limit: maxCapsuleExpandedTotal}
	tr := tar.NewReader(budget)
	var extractedFiles []BackupFile

	root, err := prepareTargetDir(targetDir)
	if err != nil {
		return nil, err
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		// Only regular files are ever written by CreateCapsule. Symlinks, hardlinks, device
		// nodes and directories in the archive have no legitimate use here and each is a way
		// to write somewhere the restore was not asked to touch.
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: %s (type %q)", ErrCapsuleEntryType, hdr.Name, string(hdr.Typeflag))
		}
		if len(extractedFiles) >= maxCapsuleFiles {
			return nil, fmt.Errorf("%w: more than %d files", ErrCapsuleTooLarge, maxCapsuleFiles)
		}
		if hdr.Size < 0 || hdr.Size > maxCapsuleFileBytes {
			return nil, fmt.Errorf("%w: %s declares %d bytes", ErrCapsuleTooLarge, hdr.Name, hdr.Size)
		}

		cleanName, err := safeRelPath(hdr.Name)
		if err != nil {
			return nil, err
		}

		// LimitReader caps what a lying header can actually deliver; the +1 byte is how an
		// over-long entry is detected rather than silently truncated.
		data, err := io.ReadAll(io.LimitReader(tr, maxCapsuleFileBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxCapsuleFileBytes {
			return nil, fmt.Errorf("%w: %s", ErrCapsuleTooLarge, hdr.Name)
		}

		// Clamp to owner-only. A restored capsule carries signing and encryption keys, and
		// an archive header is the attacker's field to fill: nothing in it should be able to
		// land a group- or world-readable key on disk.
		mode := os.FileMode(hdr.Mode).Perm() & 0700
		if mode == 0 {
			mode = 0600
		}
		extractedFiles = append(extractedFiles, BackupFile{Path: cleanName, Data: data, Mode: int64(mode)})

		if root != "" {
			if err := writeInto(root, cleanName, data, mode); err != nil {
				return nil, err
			}
		}
	}

	return extractedFiles, nil
}

// countingReader fails the whole extraction once the archive has expanded past its budget,
// instead of letting io.LimitReader report a silent early EOF that looks like a short archive.
type countingReader struct {
	r     io.Reader
	limit int64
	seen  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.seen += int64(n)
	if c.seen > c.limit {
		return n, fmt.Errorf("%w: expanded past %d bytes", ErrCapsuleTooLarge, c.limit)
	}
	return n, err
}

// safeRelPath rejects any archive member name that does not stay inside the target.
func safeRelPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	// Windows-style separators and drive letters are traversal on the platforms that honour
	// them and meaningless noise on the ones that do not.
	if strings.ContainsRune(name, '\\') || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, name)
	}
	return clean, nil
}

// prepareTargetDir returns the directory to unpack into, creating it if needed. An existing
// non-empty directory is refused: extracting over unknown contents is how a pre-planted
// symlink gets a chance to redirect a write.
func prepareTargetDir(targetDir string) (string, error) {
	if targetDir == "" {
		return "", nil
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return "", err
	}
	if len(entries) > 0 {
		return "", fmt.Errorf("%w: %s", ErrTargetNotEmpty, targetDir)
	}
	// Resolve once, so every later containment check compares against a real path rather
	// than one that still contains a symlinked component.
	resolved, err := filepath.EvalSymlinks(targetDir)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// writeInto creates one archive member beneath root, refusing to follow any symlink and
// refusing to overwrite an existing name.
func writeInto(root, relPath string, data []byte, mode os.FileMode) error {
	destPath := filepath.Join(root, relPath)
	if destPath != root && !strings.HasPrefix(destPath, root+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s", ErrPathTraversal, relPath)
	}

	// Build the parent chain a component at a time. MkdirAll would happily walk through a
	// symlinked component that a previous entry (or a racing process) planted.
	dir := root
	for _, part := range strings.Split(filepath.Dir(relPath), string(os.PathSeparator)) {
		if part == "." || part == "" {
			continue
		}
		dir = filepath.Join(dir, part)
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrPathTraversal, dir)
		}
	}

	f, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Close()
}
