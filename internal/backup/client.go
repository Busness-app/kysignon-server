package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kysignon-server/internal/config"
)

// Relative paths inside a capsule. The restore drill and the restore command both have to
// find the same files the collector wrote.
const (
	dbRelPath        = "data/kysignon.db"
	keyRelPath       = "data/jwt_rs256.key"
	encKeyRelPath    = "data/encryption.key"
	secretKeyRelPath = "data/secret.key"
	recoveryPubPath  = "data/recovery.pub"
	configRelPath    = "config/kysignon.json"
)

// uploadTimeout bounds one deposit. A container is at most 384 MiB and kyrecovery gives the
// read fifteen minutes; the claim keeps the short timeout because it carries a few hundred bytes.
const uploadTimeout = 15 * time.Minute

// KyRecoveryClient is the product half of the pairing and deposit contract.
type KyRecoveryClient struct {
	client       *http.Client
	allowPrivate bool
}

// NewKyRecoveryClient builds the client. allowPrivate is Config.BackupAllowPrivateRecovery:
// with it, a KyRecovery on the operator's LAN is dialled; without it, only public addresses.
// HTTPS is required either way.
func NewKyRecoveryClient(allowPrivate bool) *KyRecoveryClient {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if allowedIP(ip, allowPrivate) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		if allowPrivate {
			return nil, errors.New("recovery host resolves only to loopback or unroutable addresses")
		}
		return nil, errors.New("recovery host resolves only to private or reserved addresses; set KYSIGNON_BACKUP_ALLOW_PRIVATE_RECOVERY=true for a KyRecovery on your own network")
	}}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: refuseRedirect}
	return &KyRecoveryClient{client: client, allowPrivate: allowPrivate}
}

// refuseRedirect is the client's redirect policy: none. A validated destination must not be
// able to bounce a claim or a sealed capsule to a host the operator never named, and nothing
// in the deposit contract needs a redirect. Go would otherwise replay the POST body on a 308.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("KyRecovery redirected to %s; redirects are refused", req.URL.Redacted())
}

// ValidateRecoveryURL is the rule for where this server will send a capsule: HTTPS, no
// credentials, and unless allowPrivate, not a private or reserved address. Handlers call it
// before storing a URL.
func ValidateRecoveryURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("recovery URL must be an HTTPS URL without credentials")
	}
	// The API path is appended to this URL; a query or fragment would silently send the
	// claim and the capsule to the host's root instead of the deposit endpoint.
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("recovery URL must not carry a query string or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !allowedIP(ip, allowPrivate) {
		if allowPrivate {
			return errors.New("recovery URL cannot target a loopback or unroutable address")
		}
		return errors.New("recovery URL cannot target a private or reserved address; set KYSIGNON_BACKUP_ALLOW_PRIVATE_RECOVERY=true for a KyRecovery on your own network")
	}
	return nil
}

// allowedIP is isPublicIP, or with allowPrivate the wider rule for an operator's own network:
// private ranges and carrier-grade NAT (Tailscale) are in; loopback, link-local, multicast
// and the unspecified address never are, because none of them is a KyRecovery.
func allowedIP(ip net.IP, allowPrivate bool) bool {
	if !allowPrivate {
		return isPublicIP(ip)
	}
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, n := range reservedRanges[1:] {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// reservedRanges are the non-routable or special-purpose blocks net.IP's own predicates miss:
// carrier-grade NAT (which is also every Tailscale address), IETF protocol assignments,
// benchmarking, class E, and the NAT64 well-known prefix.
var reservedRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96"} {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	return out
}()

// isPublicIP is the default rule for where a capsule may be sent. The backup client never
// honours AllowPrivateCallbacks: that setting is for paired systems' callbacks. Its own
// opt-in is BackupAllowPrivateRecovery, because a KyRecovery on a private address makes every
// scheduled deposit an unattended request into that network and deserves its own decision.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, n := range reservedRanges {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// endpoint joins the server URL and an API path after checking the URL is one the client is
// willing to talk to.
func endpoint(serverURL, path string, allowPrivate bool) (string, error) {
	u := strings.TrimRight(serverURL, "/") + path
	if err := ValidateRecoveryURL(u, allowPrivate); err != nil {
		return "", fmt.Errorf("invalid recovery URL: %w", err)
	}
	return u, nil
}

// PairingResult is what a completed pairing yields: the bearer token for deposits and the
// suite recovery public key with its custodian topology. A claim that returns no key is not a
// completed pairing.
type PairingResult struct {
	APIToken string
	Key      RecoveryKey
}

// ClaimPairing exchanges a 6-digit ephemeral pairing PIN with KyRecovery for a permanent API
// bearer token and the suite recovery public key to seal backups to.
//
// serviceName is sent explicitly: kyrecovery pins whatever the claimer sends and refuses every
// later deposit whose manifest names a different service, so it must be the same value Seal
// is given.
func (c *KyRecoveryClient) ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (PairingResult, error) {
	u, err := endpoint(serverURL, "/api/pairing/claim", c.allowPrivate)
	if err != nil {
		return PairingResult{}, err
	}
	bodyBytes, _ := json.Marshal(map[string]string{
		"pairing_code": strings.TrimSpace(pairingCode),
		"service_name": serviceName,
		"app_name":     appName,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(bodyBytes))
	if err != nil {
		return PairingResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return PairingResult{}, fmt.Errorf("pairing claim request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PairingResult{}, fmt.Errorf("pairing claim rejected (%d): %s", resp.StatusCode, remoteMessage(resp.Body))
	}
	var claimResp struct {
		APIToken          string `json:"api_token"`
		RecoveryPublicKey string `json:"recovery_public_key"` // std base64 of 1216 bytes
		Threshold         int    `json:"threshold"`
		TotalShares       int    `json:"total_shares"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&claimResp); err != nil {
		return PairingResult{}, err
	}
	if claimResp.APIToken == "" {
		return PairingResult{}, errors.New("empty api_token in claim response")
	}
	pkBytes, err := base64.StdEncoding.DecodeString(claimResp.RecoveryPublicKey)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	pk, err := recoverykey.ParsePublicKey(pkBytes)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	if !validTopology(claimResp.Threshold, claimResp.TotalShares) {
		return PairingResult{}, fmt.Errorf("claim response: %d-of-%d is not a custodian topology", claimResp.Threshold, claimResp.TotalShares)
	}
	return PairingResult{
		APIToken: claimResp.APIToken,
		Key:      RecoveryKey{Public: pk, Threshold: claimResp.Threshold, TotalShares: claimResp.TotalShares},
	}, nil
}

// ErrRemote marks an error that came from the wire or from KyRecovery itself, as opposed to
// one raised here before any byte was sent. Handlers answer the two differently.
var ErrRemote = errors.New("backup: KyRecovery")

// Receipt is kyrecovery's record of one deposit. Digest and SizeBytes are the only values
// the store computed itself; a restore compares CapsuleID against the capsule in hand.
type Receipt struct {
	CapsuleID   string    `json:"capsule_id"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"size_bytes"`
	DepositedAt time.Time `json:"deposited_at"`
}

// Deposit hands a sealed container to kyrecovery and returns its receipt. The receipt's
// digest is checked against the bytes sent so a deposit counts only when kyrecovery stored
// exactly what left here. 200 is kyrecovery re-sending the receipt for bytes it already
// holds, which is a success.
func (c *KyRecoveryClient) Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error) {
	u, err := endpoint(serverURL, "/api/backup/deposit", c.allowPrivate)
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(container))
	if err != nil {
		return Receipt{}, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	// The client's own timeout is sized for a claim; the upload budget is the context above.
	upload := *c.client
	upload.Timeout = 0
	resp, err := upload.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit request failed: %w", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("%w: deposit rejected (%d): %s", ErrRemote, resp.StatusCode, remoteMessage(resp.Body))
	}
	var rcpt Receipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rcpt); err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit receipt: %w", ErrRemote, err)
	}
	sum := sha256.Sum256(container)
	if want := hex.EncodeToString(sum[:]); rcpt.Digest != want {
		return Receipt{}, fmt.Errorf("%w: deposit receipt digest %s does not match the container sent (%s)", ErrRemote, rcpt.Digest, want)
	}
	if rcpt.SizeBytes != int64(len(container)) {
		return Receipt{}, fmt.Errorf("%w: deposit receipt size %d does not match the %d bytes sent", ErrRemote, rcpt.SizeBytes, len(container))
	}
	if rcpt.CapsuleID == "" {
		return Receipt{}, fmt.Errorf("%w: deposit receipt has no capsule_id", ErrRemote)
	}
	return rcpt, nil
}

// auditTextLimit bounds any text that reaches the audit log from outside the process.
const auditTextLimit = 200

// AuditSafe makes a string fit for an audit record: printable characters only, cut at
// auditTextLimit. Remote bodies and operator input go through it before they are stored,
// because the audit table rides inside every capsule and grows with whatever lands in it.
func AuditSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= auditTextLimit {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// remoteMessage is what a KyRecovery error body contributes to an error: a bounded, printable
// excerpt, never the raw body.
func remoteMessage(body io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(body, 4<<10))
	return AuditSafe(string(b))
}

// Snapshotter produces a transactionally consistent copy of the live database. The store
// implements it with VACUUM INTO through the live connection: copying the main file misses
// every commit still in the -wal.
type Snapshotter interface {
	SnapshotTo(destPath string) error
}

// Payload is what a backup carries: the members and the metadata the manifest records.
type Payload struct {
	ServiceName        string
	AppVersion         string
	Files              []BackupFile
	Dependencies       map[string]any
	VerificationRecipe map[string]any
}

// Members lists what a capsule from this instance carries, in the order CollectSealable
// packs it, so the admin screen can say what is being backed up without sealing anything.
func Members(cfg *config.Config) []string {
	m := []string{dbRelPath, keyRelPath, encKeyRelPath, secretKeyRelPath}
	if _, err := os.Stat(RecoveryKeyPath(cfg.DataDir)); err == nil {
		m = append(m, recoveryPubPath)
	}
	return append(m, configRelPath)
}

// CollectSealable gathers everything a restore needs. Every member is secret or the means to
// one, so the payload leaves the process only inside a sealed capsule.
//
// A missing database, signing key or deployment key is fatal. A well-formed capsule that
// cannot restore the service is worse than no capsule: the drill passes, the operator
// believes they are covered, and the gap surfaces only when production is already gone.
func CollectSealable(cfg *config.Config, snap Snapshotter, appVersion string) (*Payload, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("backup requires a database path; none is configured")
	}
	if snap == nil {
		return nil, errors.New("backup requires a live database handle to snapshot")
	}
	var files []BackupFile

	scratch, err := os.MkdirTemp(cfg.DataDir, "snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	snapPath := filepath.Join(scratch, "kysignon.db")
	if err := snap.SnapshotTo(snapPath); err != nil {
		return nil, err
	}
	dbBytes, err := os.ReadFile(snapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read database snapshot: %w", err)
	}
	if len(dbBytes) == 0 {
		return nil, errors.New("database snapshot is empty")
	}
	files = append(files, BackupFile{Path: dbRelPath, Data: dbBytes, Mode: 0600})

	// The RSA signing key: without it every issued token and OIDC client breaks on restore.
	if cfg.RSAKeyPath == "" {
		return nil, errors.New("backup requires an RSA signing key path; none is configured")
	}
	keyBytes, err := os.ReadFile(cfg.RSAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA signing key %s: %w", cfg.RSAKeyPath, err)
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("RSA signing key %s is empty", cfg.RSAKeyPath)
	}
	files = append(files, BackupFile{Path: keyRelPath, Data: keyBytes, Mode: 0600})

	// The deployment key material. The database ships every TOTP secret and paired-system
	// token encrypted under the encryption key, so a capsule without it restores a directory
	// whose MFA state is permanently unreadable. The secret key: without it every session
	// and CSRF token minted before the restore is silently invalid. Taken from the loaded
	// config, so a deployment that supplies them by environment is backed up as faithfully.
	for _, k := range []struct {
		relPath  string
		material []byte
		name     string
	}{
		{encKeyRelPath, cfg.EncryptionKey, "encryption key"},
		{secretKeyRelPath, cfg.SecretKey, "secret key"},
	} {
		if len(k.material) != config.KeyLength {
			return nil, fmt.Errorf("backup requires a %d-byte %s; the loaded one is %d bytes",
				config.KeyLength, k.name, len(k.material))
		}
		files = append(files, BackupFile{Path: k.relPath, Data: k.material, Mode: 0600})
	}

	// The suite recovery public key rides along when this instance is paired, so a restore
	// comes back paired rather than steering the operator into a re-pair.
	if pub, err := os.ReadFile(RecoveryKeyPath(cfg.DataDir)); err == nil {
		files = append(files, BackupFile{Path: recoveryPubPath, Data: pub, Mode: 0600})
	}

	cfgJSON, err := json.MarshalIndent(map[string]any{
		"app_name":                cfg.AppName,
		"version":                 appVersion,
		"port":                    cfg.Port,
		"issuer_url":              cfg.IssuerURL,
		"data_dir":                cfg.DataDir,
		"allow_private_callbacks": cfg.AllowPrivateCallbacks,
		"secure_cookies":          cfg.SecureCookies,
		"session_ttl_sec":         int64(cfg.SessionTTL / time.Second),
		"session_idle_ttl_sec":    int64(cfg.SessionIdleTTL / time.Second),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append(files, BackupFile{Path: configRelPath, Data: cfgJSON, Mode: 0600})

	portNum, _ := strconv.Atoi(cfg.Port)
	if portNum == 0 {
		portNum = 5867
	}
	reqFiles := make([]string, 0, len(files))
	for _, f := range files {
		reqFiles = append(reqFiles, f.Path)
	}
	return &Payload{
		ServiceName: cfg.AppName,
		AppVersion:  appVersion,
		Files:       files,
		Dependencies: map[string]any{
			"ports": []int{portNum},
			"env":   []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
		},
		VerificationRecipe: map[string]any{
			"check_sqlite_integrity": true,
			"sqlite_paths":           []string{dbRelPath},
			"required_files":         reqFiles,
			// The drill asserts these tables exist and the admin directory is non-empty.
			// PRAGMA integrity_check only proves the file is not corrupt.
			"required_tables":   []string{"users", "oauth_clients", "mfa_methods", "paired_systems"},
			"require_any_admin": true,
			// Proving the restored bytes are also usable: the encrypted columns still read
			// and the service could issue a token.
			"encryption_key_file":     encKeyRelPath,
			"secret_key_file":         secretKeyRelPath,
			"rsa_key_file":            keyRelPath,
			"prove_secret_decryption": true,
			"prove_token_signing":     true,
			"expected_env":            []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
			"expected_ports":          []int{portNum},
		},
	}, nil
}
