package backup

import (
	"fmt"
	"os"
	"strings"

	"github.com/Busness-app/ky-primitives/capsule"
)

// MaxCapsuleFileBytes and MaxCapsuleTotalBytes are the caps capsule enforces on a payload,
// named here so an operator-facing message and the library can never disagree.
const (
	MaxCapsuleFileBytes  = capsule.MaxFileBytes
	MaxCapsuleTotalBytes = capsule.MaxExpandedBytes
)

// TooLargeMessage is what an operator is told when a backup outgrows a capsule.
var TooLargeMessage = fmt.Sprintf("Backup exceeds the capsule size limit (%d MiB per file, %d MiB total)",
	MaxCapsuleFileBytes>>20, MaxCapsuleTotalBytes>>20)

// BackupFile is one member of a capsule's payload, as the collectors produce it.
type BackupFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode int64  `json:"mode"`
}

// Seal writes a kycap/3 container sealed to the suite recovery public key. The product
// holds nothing afterwards that opens it; only the custodians' shares do.
func Seal(serviceName, appVersion string, files []BackupFile, deps, recipe map[string]any, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	if key.Public.IsZero() {
		return nil, capsule.Manifest{}, ErrNotPaired
	}
	return capsule.Seal(serviceName, appVersion, toCapsuleFiles(files), deps, recipe, key.Threshold, key.TotalShares, key.Public)
}

func toCapsuleFiles(files []BackupFile) []capsule.File {
	out := make([]capsule.File, 0, len(files))
	for _, f := range files {
		out = append(out, capsule.File{Path: f.Path, Content: f.Data, Mode: os.FileMode(f.Mode)})
	}
	return out
}

// FilenameSafe reduces a capsule ID to [A-Za-z0-9._-]. The ID embeds KY_APP_NAME, which an
// operator sets, so it can carry a quote, a slash or a newline that would break out of a
// Content-Disposition header or escape the directory a CLI export writes into.
func FilenameSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, s)
}
