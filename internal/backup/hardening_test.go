package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
)

// sealTar wraps a hand-built tar stream as a capsule, so extraction can be tested against
// archives a healthy server would never produce. A capsule decrypting under a quorum proves
// who built it, not that what they built is safe to unpack.
func sealTar(t *testing.T, build func(*tar.Writer)) (*Capsule, []byte) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	payload := buf.Bytes()
	sum := sha256.Sum256(payload)
	key := bytes.Repeat([]byte{0x7c}, 32)
	ct, err := crypto.EncryptAESGCM(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	return &Capsule{
		Manifest:   Manifest{CapsuleID: "cap-test", PayloadHash: hex.EncodeToString(sum[:]), Threshold: 2, TotalShares: 3},
		Ciphertext: []byte(ct),
	}, key
}

func writeEntry(tw *tar.Writer, name string, data []byte) {
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Now()})
	_, _ = tw.Write(data)
}

func TestExtractRejectsDecompressionBomb(t *testing.T) {
	prevTotal := maxCapsuleExpandedTotal
	maxCapsuleExpandedTotal = 64 << 10
	defer func() { maxCapsuleExpandedTotal = prevTotal }()

	// Highly compressible, so the container stays small while the expansion does not.
	capsule, key := sealTar(t, func(tw *tar.Writer) {
		writeEntry(tw, "data/kysignon.db", bytes.Repeat([]byte{0}, 4<<20))
	})

	if _, err := ExtractCapsule(capsule, key, t.TempDir()+"/out"); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("a capsule expanding far past the budget was accepted: %v", err)
	}
}

func TestExtractRejectsTooManyFiles(t *testing.T) {
	prevFiles := maxCapsuleFiles
	maxCapsuleFiles = 4
	defer func() { maxCapsuleFiles = prevFiles }()

	capsule, key := sealTar(t, func(tw *tar.Writer) {
		for i := 0; i < 50; i++ {
			writeEntry(tw, filepath.Join("data", string(rune('a'+i%26))+string(rune('a'+i/26))), []byte("x"))
		}
	})

	if _, err := ExtractCapsule(capsule, key, t.TempDir()+"/out"); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("a capsule with far more members than permitted was accepted: %v", err)
	}
}

func TestExtractRejectsOversizedSingleFile(t *testing.T) {
	prevFile := maxCapsuleFileBytes
	maxCapsuleFileBytes = 1 << 10
	defer func() { maxCapsuleFileBytes = prevFile }()

	capsule, key := sealTar(t, func(tw *tar.Writer) {
		writeEntry(tw, "data/kysignon.db", bytes.Repeat([]byte{1}, 8<<10))
	})

	if _, err := ExtractCapsule(capsule, key, t.TempDir()+"/out"); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("an oversized member was accepted: %v", err)
	}
}

// A tar symlink or directory entry is a write primitive aimed outside the target. Nothing
// this server produces needs one.
func TestExtractRejectsNonRegularEntries(t *testing.T) {
	for name, hdr := range map[string]*tar.Header{
		"symlink":  {Name: "data/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0777},
		"hardlink": {Name: "data/evil", Typeflag: tar.TypeLink, Linkname: "/etc/passwd", Mode: 0777},
		"device":   {Name: "data/evil", Typeflag: tar.TypeChar, Mode: 0666},
		"dir":      {Name: "data/evil", Typeflag: tar.TypeDir, Mode: 0755},
	} {
		t.Run(name, func(t *testing.T) {
			capsule, key := sealTar(t, func(tw *tar.Writer) { _ = tw.WriteHeader(hdr) })
			if _, err := ExtractCapsule(capsule, key, t.TempDir()+"/out"); !errors.Is(err, ErrCapsuleEntryType) {
				t.Fatalf("a %s entry was accepted: %v", name, err)
			}
		})
	}
}

func TestExtractRejectsTraversalNames(t *testing.T) {
	for _, name := range []string{"../escape", "data/../../escape", "/etc/passwd", "data/../../../tmp/x"} {
		capsule, key := sealTar(t, func(tw *tar.Writer) { writeEntry(tw, name, []byte("x")) })
		if _, err := ExtractCapsule(capsule, key, t.TempDir()+"/out"); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("member %q was accepted: %v", name, err)
		}
	}
}

// A symlink already sitting under the target must not redirect a restore. This is the case
// filepath.Clean plus a HasPrefix check does not catch: the path stays inside the target and
// the kernel follows the link on write.
func TestExtractDoesNotFollowPlantedSymlink(t *testing.T) {
	tmp := t.TempDir()
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(tmp, "restore")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "data")); err != nil {
		t.Fatal(err)
	}

	capsule, key := sealTar(t, func(tw *tar.Writer) { writeEntry(tw, "data/secret", []byte("overwritten")) })

	// A directory holding anything at all is refused outright, which is what makes the
	// planted link unreachable in the first place.
	_, err := ExtractCapsule(capsule, key, target)
	if !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("extraction into a pre-populated directory was allowed: %v", err)
	}
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "original" {
		t.Fatalf("the file behind the planted symlink was modified: %q %v", got, err)
	}
}

func TestExtractAcceptsAWellFormedCapsule(t *testing.T) {
	capsule, key := sealTar(t, func(tw *tar.Writer) {
		writeEntry(tw, "data/kysignon.db", []byte("db"))
		writeEntry(tw, "config/kysignon.json", []byte("{}"))
	})
	out := filepath.Join(t.TempDir(), "restore")
	files, err := ExtractCapsule(capsule, key, out)
	if err != nil {
		t.Fatalf("a legitimate capsule was rejected: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if got, err := os.ReadFile(filepath.Join(out, "data/kysignon.db")); err != nil || string(got) != "db" {
		t.Fatalf("restored content is wrong: %q %v", got, err)
	}
}

// The custody claim is "2 of 3 custodians", not "one administrator, three clicks".
func TestOneCustodianCannotCollectAQuorum(t *testing.T) {
	ks := NewKitStore()
	capsule, _, err := CreateCapsule("KySignOn", "1.0.0",
		[]BackupFile{{Path: "data/kysignon.db", Data: []byte("db"), Mode: 0600}}, nil, nil, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	kit, err := ks.Create(capsule)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ks.TakeShard(kit.ID, 1, "admin-a", false); err != nil {
		t.Fatalf("the first shard was refused: %v", err)
	}
	if _, err := ks.TakeShard(kit.ID, 2, "admin-a", false); !errors.Is(err, ErrCustodyQuorum) {
		t.Fatalf("one principal collected a quorum: %v", err)
	}
	// A different custodian is exactly what the model calls for.
	if _, err := ks.TakeShard(kit.ID, 2, "admin-b", false); err != nil {
		t.Fatalf("a second custodian was refused: %v", err)
	}
	// And a shard is still handed out only once.
	if _, err := ks.TakeShard(kit.ID, 1, "admin-b", false); !errors.Is(err, ErrShardNotFound) {
		t.Fatalf("a collected shard was served again: %v", err)
	}
}

func TestShardRequiresAnIdentifiedCustodian(t *testing.T) {
	ks := NewKitStore()
	capsule, _, _ := CreateCapsule("KySignOn", "1.0.0",
		[]BackupFile{{Path: "data/kysignon.db", Data: []byte("db"), Mode: 0600}}, nil, nil, 2, 3)
	kit, _ := ks.Create(capsule)
	if _, err := ks.TakeShard(kit.ID, 1, "  ", false); !errors.Is(err, ErrNoCustodian) {
		t.Fatalf("a shard was released to an unidentified caller: %v", err)
	}
}

// The sole-administrator escape hatch exists so a one-admin deployment still has backups. It
// must be exactly that, and not the default.
func TestSoleCustodianOverrideIsOptIn(t *testing.T) {
	ks := NewKitStore()
	capsule, _, _ := CreateCapsule("KySignOn", "1.0.0",
		[]BackupFile{{Path: "data/kysignon.db", Data: []byte("db"), Mode: 0600}}, nil, nil, 2, 3)
	kit, _ := ks.Create(capsule)
	for i := 1; i <= 3; i++ {
		if _, err := ks.TakeShard(kit.ID, i, "only-admin", true); err != nil {
			t.Fatalf("sole custodian was refused shard %d: %v", i, err)
		}
	}
}

// fakeSettings is a settings table with no encryption of its own, so the test can look at
// exactly what would land in the database.
type fakeSettings map[string]string

func (f fakeSettings) GetSetting(k string) (string, error) { return f[k], nil }
func (f fakeSettings) SetSetting(k, v string) error        { f[k] = v; return nil }

func TestRecoveryTokenIsNeverStoredInTheClear(t *testing.T) {
	settings := fakeSettings{}
	key := bytes.Repeat([]byte{0x3a}, 32)
	const token = "kyrecovery-bearer-6f2b9c1d4e8a7f30"

	if err := SaveRecoveryToken(settings, key, token); err != nil {
		t.Fatal(err)
	}
	for k, v := range settings {
		if strings.Contains(v, token) {
			t.Fatalf("setting %q holds the recovery token verbatim", k)
		}
	}

	got, err := LoadRecoveryToken(settings, key)
	if err != nil || got != token {
		t.Fatalf("LoadRecoveryToken = %q, %v; want the original token", got, err)
	}

	// Domain separation: a value sealed for this setting must not decrypt under the bare
	// deployment key, so a ciphertext cannot be relocated between columns.
	if _, err := crypto.DecryptAESGCM(key, settings[recoveryTokenSetting]); err == nil {
		t.Fatal("the stored token decrypts under the undifferentiated deployment key")
	}

	// A wrong deployment key must fail loudly rather than yield garbage.
	if _, err := LoadRecoveryToken(settings, bytes.Repeat([]byte{0x99}, 32)); err == nil {
		t.Fatal("the token decrypted under the wrong key")
	}
}

// A deployment paired by an older build has the token sitting in plaintext. It is re-sealed
// on first read; refusing it instead would mean an operator with no working backup push.
func TestLegacyPlaintextRecoveryTokenIsMigrated(t *testing.T) {
	settings := fakeSettings{legacyRecoveryTokenSetting: "legacy-token-value"}
	key := bytes.Repeat([]byte{0x11}, 32)

	got, err := LoadRecoveryToken(settings, key)
	if err != nil || got != "legacy-token-value" {
		t.Fatalf("LoadRecoveryToken = %q, %v", got, err)
	}
	if settings[legacyRecoveryTokenSetting] != "" {
		t.Error("the plaintext copy was left behind after migration")
	}
	if settings[recoveryTokenSetting] == "" {
		t.Fatal("no sealed copy was written")
	}
	if strings.Contains(settings[recoveryTokenSetting], "legacy-token-value") {
		t.Fatal("the migrated value is still readable")
	}
}

// The drill is the only thing standing between "we have backups" and finding out during an
// outage. A capsule that restores a database of ciphertext with no key must fail it.
func TestDrillFailsWhenTheEncryptionKeyIsMissing(t *testing.T) {
	files := []BackupFile{
		{Path: dbRelPath, Data: []byte("not-a-real-db"), Mode: 0600},
		{Path: keyRelPath, Data: []byte("key"), Mode: 0600},
	}
	recipe := map[string]interface{}{
		"encryption_key_file":     encKeyRelPath,
		"secret_key_file":         secretKeyRelPath,
		"prove_secret_decryption": true,
	}
	capsule, key, err := CreateCapsule("KySignOn", "1.0.0", files, nil, recipe, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	result, err := RunRestoreDrill(t.Context(), capsule, key)
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Fatal("a capsule with no encryption key passed the restore drill")
	}
	var sawKeyCheck bool
	for _, c := range result.Checks {
		if strings.Contains(c.Name, "MFA Secret Decryption") && !c.Passed {
			sawKeyCheck = true
		}
	}
	if !sawKeyCheck {
		t.Fatalf("the drill did not report the missing encryption key: %+v", result.Checks)
	}
}
