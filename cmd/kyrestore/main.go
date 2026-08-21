// Command kyrestore reconstructs a KySignOn backup from an exported recovery kit and
// nothing else. It is the tool the custodian cards tell operators to run, so it must work
// with no live server, no network, and no state beyond the .kycap container and a quorum of
// shards.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Yoshiofthewire/kysignon-server/internal/backup"
)

type shardFlag []backup.Share

func (s *shardFlag) String() string { return fmt.Sprintf("%d shard(s)", len(*s)) }

func (s *shardFlag) Set(value string) error {
	index, encoded, ok := strings.Cut(value, ":")
	if !ok {
		return fmt.Errorf("shard must be given as INDEX:HEX, got %q", value)
	}
	n, err := strconv.Atoi(strings.TrimSpace(index))
	if err != nil || n <= 0 || n > 255 {
		return fmt.Errorf("shard index %q must be a number between 1 and 255", index)
	}
	share, err := backup.ParseShardHex(n, encoded)
	if err != nil {
		return err
	}
	*s = append(*s, share)
	return nil
}

func main() {
	var shards shardFlag
	capsulePath := flag.String("capsule", "", "path to the exported .kycap container")
	outDir := flag.String("out", "", "directory to write the restored files into")
	flag.Var(&shards, "shard", "custodian shard as INDEX:HEX (repeat for each custodian)")
	flag.Parse()

	if err := run(*capsulePath, *outDir, shards); err != nil {
		fmt.Fprintf(os.Stderr, "kyrestore: %v\n", err)
		os.Exit(1)
	}
}

func run(capsulePath, outDir string, shards []backup.Share) error {
	if capsulePath == "" || outDir == "" {
		return fmt.Errorf("both -capsule and -out are required")
	}
	raw, err := os.ReadFile(capsulePath)
	if err != nil {
		return err
	}
	capsule, err := backup.ParseCapsule(raw)
	if err != nil {
		return err
	}

	threshold := capsule.Manifest.Threshold
	if len(shards) < threshold {
		return fmt.Errorf("this capsule needs %d shards; %d were supplied", threshold, len(shards))
	}

	key, err := backup.CombineShares(shards, threshold)
	if err != nil {
		return fmt.Errorf("failed to recombine shards: %w", err)
	}

	// ExtractCapsule verifies the payload hash before writing anything, so a wrong quorum
	// or a tampered container fails instead of producing a plausible-looking restore.
	files, err := backup.ExtractCapsule(capsule, key, outDir)
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	fmt.Printf("Restored capsule %s (created %s)\n",
		capsule.Manifest.CapsuleID, capsule.Manifest.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	for _, f := range files {
		fmt.Printf("  %s (%d bytes)\n", filepath.Join(outDir, f.Path), len(f.Data))
	}
	fmt.Printf("Payload hash verified: %s\n", capsule.Manifest.PayloadHash)
	return nil
}
