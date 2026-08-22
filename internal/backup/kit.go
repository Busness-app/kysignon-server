package backup

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CapsuleFileFormat identifies the on-disk .kycap container version.
const CapsuleFileFormat = "kycap/1"

// KitTTL bounds how long a kit's shards stay in memory waiting to be collected.
const KitTTL = 30 * time.Minute

var (
	ErrKitNotFound   = errors.New("recovery kit not found or expired")
	ErrShardNotFound = errors.New("shard not found")
	ErrShardHeld     = errors.New("this shard was already released to a different custodian; it cannot be handed to a second principal")
	ErrCustodyQuorum = errors.New("this administrator already holds the most shards one custodian may hold; a different administrator must collect the rest")
	ErrNoCustodian   = errors.New("a shard cannot be released without an identified custodian")
)

// capsuleFile is the serialized .kycap container. It deliberately carries no shards: the
// whole point of splitting the key is that the encrypted payload and the means to decrypt it
// do not travel together.
type capsuleFile struct {
	Format     string   `json:"format"`
	Manifest   Manifest `json:"manifest"`
	Ciphertext string   `json:"ciphertext"`
}

// SerializeCapsule writes the encrypted container: manifest plus ciphertext, no shards.
func SerializeCapsule(capsule *Capsule) ([]byte, error) {
	if capsule == nil || len(capsule.Ciphertext) == 0 {
		return nil, errors.New("cannot serialize a capsule with no ciphertext")
	}
	return json.MarshalIndent(capsuleFile{
		Format:     CapsuleFileFormat,
		Manifest:   capsule.Manifest,
		Ciphertext: string(capsule.Ciphertext),
	}, "", "  ")
}

// ParseCapsule reads a .kycap container back. The returned capsule has no shards; supply
// them from the custodian cards.
func ParseCapsule(raw []byte) (*Capsule, error) {
	var cf capsuleFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return nil, fmt.Errorf("not a readable .kycap container: %w", err)
	}
	if cf.Format != CapsuleFileFormat {
		return nil, fmt.Errorf("unsupported capsule format %q (expected %s)", cf.Format, CapsuleFileFormat)
	}
	if cf.Ciphertext == "" {
		return nil, errors.New("capsule container has no ciphertext")
	}
	return &Capsule{Manifest: cf.Manifest, Ciphertext: []byte(cf.Ciphertext)}, nil
}

// ParseShardHex reads a custodian shard back into a Share.
func ParseShardHex(index int, encoded string) (Share, error) {
	data, err := hex.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return Share{}, fmt.Errorf("shard %d is not valid hex: %w", index, err)
	}
	if len(data) == 0 {
		return Share{}, fmt.Errorf("shard %d is empty", index)
	}
	return Share{Index: index, Data: data}, nil
}

// Kit is a pending recovery-kit export. The encrypted capsule and each custodian shard are
// separate artifacts collected by separate authenticated requests, and each shard is bound
// to the one custodian who collected it. A single download can therefore never contain a
// reconstruction quorum, which is the property the 2-of-3 custody model claims but a
// combined document destroys.
type Kit struct {
	ID        string
	Manifest  Manifest
	Capsule   []byte
	ExpiresAt time.Time

	shards    map[int][]byte
	collected map[int]bool
	// holders records which principal took each shard. Splitting artifacts across separate
	// HTTP requests does not create separate custodians; only refusing to hand one principal
	// a reconstructable set does.
	holders map[int]string
}

// ShardState reports whether a custodian shard is still awaiting collection.
type ShardState struct {
	Index     int  `json:"index"`
	Collected bool `json:"collected"`
	// HeldBySelf marks a shard this viewer already holds, so the UI can show who still
	// needs to sign in rather than offering a button that will be refused.
	HeldBySelf bool `json:"heldBySelf,omitempty"`
}

// Shards lists every shard slot, whether it has been collected, and whether the named
// viewer is the one holding it.
func (k *Kit) Shards(viewer string) []ShardState {
	out := make([]ShardState, 0, k.Manifest.TotalShares)
	for i := 1; i <= k.Manifest.TotalShares; i++ {
		out = append(out, ShardState{
			Index:      i,
			Collected:  k.collected[i],
			HeldBySelf: viewer != "" && k.holders[i] == viewer,
		})
	}
	return out
}

// MaxPerCustodian is the most shards one principal may hold without being able to
// reconstruct the key alone.
func (k *Kit) MaxPerCustodian() int {
	if k.Manifest.Threshold <= 1 {
		return 1
	}
	return k.Manifest.Threshold - 1
}

// HeldBy counts the shards a principal has already collected from this kit.
func (k *Kit) HeldBy(custodian string) int {
	n := 0
	for _, holder := range k.holders {
		if holder == custodian {
			n++
		}
	}
	return n
}

// KitStore holds pending kits in memory only. Shards are never written to disk by the
// server: a plaintext key share on the identity host is the one place it must not be.
type KitStore struct {
	mu   sync.Mutex
	kits map[string]*Kit
	ttl  time.Duration
}

func NewKitStore() *KitStore {
	return &KitStore{kits: map[string]*Kit{}, ttl: KitTTL}
}

// Create registers a kit for collection and returns it.
func (ks *KitStore) Create(capsule *Capsule) (*Kit, error) {
	capsuleBytes, err := SerializeCapsule(capsule)
	if err != nil {
		return nil, err
	}
	if len(capsule.Shares) == 0 {
		return nil, errors.New("capsule has no key shards to distribute")
	}

	kit := &Kit{
		ID:        uuid.New().String(),
		Manifest:  capsule.Manifest,
		Capsule:   capsuleBytes,
		ExpiresAt: time.Now().UTC().Add(ks.ttl),
		shards:    map[int][]byte{},
		collected: map[int]bool{},
		holders:   map[int]string{},
	}
	for _, share := range capsule.Shares {
		data := make([]byte, len(share.Data))
		copy(data, share.Data)
		kit.shards[share.Index] = data
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.sweepLocked()
	ks.kits[kit.ID] = kit
	return kit, nil
}

// Get returns a live kit.
func (ks *KitStore) Get(id string) (*Kit, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.sweepLocked()
	kit, ok := ks.kits[id]
	if !ok {
		return nil, ErrKitNotFound
	}
	return kit, nil
}

// TakeShard binds one shard to one identified custodian and returns it. The same custodian
// may fetch the same shard again; a different principal never can.
//
// Custody separation is a property of *who holds a shard*, not of how many times it was
// downloaded. Deleting the bytes on the first successful hand-off bought nothing — the
// holder check below already prevents a second principal from taking it — and cost
// everything: an audit-write failure, a full disk, or a client that disconnected mid-
// response destroyed the only copy of the shard and left the kit unrecoverable. Re-issuing
// to the custodian who already holds it hands them nothing they do not already have, so the
// download path is idempotent and no failure on it can destroy recovery material.
//
// Shards still leave memory only via Discard or TTL expiry, and are never written to disk.
//
// A custodian may hold at most threshold-1 shards, so no single principal can ever assemble
// a quorum: the "2-of-3" claim is otherwise satisfied by one administrator clicking three
// times. allowSoleCustodian lifts that cap for a deployment that genuinely has only one
// administrator, where the alternative is an unusable recovery kit and therefore no backup
// at all; the caller is responsible for establishing that and for recording it.
func (ks *KitStore) TakeShard(id string, index int, custodian string, allowSoleCustodian bool) (Share, error) {
	if strings.TrimSpace(custodian) == "" {
		return Share{}, ErrNoCustodian
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.sweepLocked()
	kit, ok := ks.kits[id]
	if !ok {
		return Share{}, ErrKitNotFound
	}
	data, ok := kit.shards[index]
	if !ok {
		return Share{}, ErrShardNotFound
	}
	if holder, taken := kit.holders[index]; taken {
		if holder != custodian {
			return Share{}, ErrShardHeld
		}
		// A repeat fetch by the existing holder: already counted against their cap, and it
		// discloses nothing new.
		return Share{Index: index, Data: data}, nil
	}
	if !allowSoleCustodian && kit.HeldBy(custodian) >= kit.MaxPerCustodian() {
		return Share{}, ErrCustodyQuorum
	}
	kit.collected[index] = true
	kit.holders[index] = custodian
	return Share{Index: index, Data: data}, nil
}

// Discard drops a kit and zeroizes any uncollected shards.
func (ks *KitStore) Discard(id string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.discardLocked(id)
}

func (ks *KitStore) discardLocked(id string) {
	kit, ok := ks.kits[id]
	if !ok {
		return
	}
	for i, data := range kit.shards {
		for j := range data {
			data[j] = 0
		}
		delete(kit.shards, i)
	}
	kit.holders = map[int]string{}
	delete(ks.kits, id)
}

func (ks *KitStore) sweepLocked() {
	now := time.Now().UTC()
	for id, kit := range ks.kits {
		if now.After(kit.ExpiresAt) {
			ks.discardLocked(id)
		}
	}
}
