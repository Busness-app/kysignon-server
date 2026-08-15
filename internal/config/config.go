package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// Config represents runtime application configuration.
type Config struct {
	Port              string
	IssuerURL         string
	DBPath            string
	DataDir           string
	SecretKey         []byte
	EncryptionKey     []byte
	RSAKeyPath        string
	TrustedProxyCIDRs []string
	BootstrapUser     string
	BootstrapPass     string
}

// Load loads configuration from environment variables with safe defaults.
func Load() (*Config, error) {
	dataDir := getEnv("KYSIGNON_DATA_DIR", "./data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}

	dbPath := getEnv("KYSIGNON_DB_PATH", filepath.Join(dataDir, "kysignon.db"))
	rsaKeyPath := getEnv("KYSIGNON_RSA_KEY_PATH", filepath.Join(dataDir, "jwt_rs256.key"))

	port := getEnv("KYSIGNON_PORT", "5867")
	issuerURL := strings.TrimRight(getEnv("KYSIGNON_ISSUER_URL", "http://localhost:"+port), "/")

	// Secret key for cookie signing / session hashes
	secretKeyHex := os.Getenv("KYSIGNON_SECRET_KEY")
	var secretKey []byte
	if secretKeyHex != "" {
		var err error
		secretKey, err = hex.DecodeString(secretKeyHex)
		if err != nil || len(secretKey) < 32 {
			secretKey = []byte(secretKeyHex)
		}
	} else {
		secretKey = getOrGenerateSecret(filepath.Join(dataDir, "secret.key"), 32)
	}

	// 256-bit encryption key for TOTP secrets at rest
	encKeyHex := os.Getenv("KYSIGNON_ENCRYPTION_KEY")
	var encKey []byte
	if encKeyHex != "" {
		var err error
		encKey, err = hex.DecodeString(encKeyHex)
		if err != nil || len(encKey) != 32 {
			encKey = padOrHashKey(encKeyHex)
		}
	} else {
		encKey = getOrGenerateSecret(filepath.Join(dataDir, "encryption.key"), 32)
	}

	var trustedCIDRs []string
	if rawCIDRs := os.Getenv("TRUSTED_PROXY_CIDRS"); rawCIDRs != "" {
		for _, cidr := range strings.Split(rawCIDRs, ",") {
			trimmed := strings.TrimSpace(cidr)
			if trimmed != "" {
				trustedCIDRs = append(trustedCIDRs, trimmed)
			}
		}
	}

	return &Config{
		Port:              port,
		IssuerURL:         issuerURL,
		DBPath:            dbPath,
		DataDir:           dataDir,
		SecretKey:         secretKey,
		EncryptionKey:     encKey,
		RSAKeyPath:        rsaKeyPath,
		TrustedProxyCIDRs: trustedCIDRs,
		BootstrapUser:     getEnv("BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapPass:     os.Getenv("BOOTSTRAP_ADMIN_PASS"),
	}, nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getOrGenerateSecret(path string, length int) []byte {
	if data, err := os.ReadFile(path); err == nil && len(data) >= length {
		return data[:length]
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	_ = os.WriteFile(path, buf, 0600)
	return buf
}

func padOrHashKey(input string) []byte {
	b := []byte(input)
	res := make([]byte, 32)
	copy(res, b)
	return res
}
