package backup

import (
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	ErrInvalidThreshold = errors.New("threshold must be <= total shares and > 1")
	ErrNotEnoughShares  = errors.New("insufficient shares to reconstruct secret")
)

// Share represents one custodian's key shard in a (k, n) Shamir Secret Sharing scheme.
type Share struct {
	Index int    `json:"index"`
	Data  []byte `json:"data"`
}

// gf256 arithmetic tables (irreducible polynomial x^8 + x^4 + x^3 + x + 1, 0x11d)
var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfExp[i+255] = byte(x)
		gfLog[byte(x)] = byte(i)
		x <<= 1
		if x >= 256 {
			x ^= 0x11d
		}
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("divide by zero in GF(256)")
	}
	diff := int(gfLog[a]) - int(gfLog[b])
	if diff < 0 {
		diff += 255
	}
	return gfExp[diff]
}

// SplitSecret splits a secret into n shares with a reconstruction threshold of k.
func SplitSecret(secret []byte, k, n int) ([]Share, error) {
	if k < 2 || k > n || n > 255 {
		return nil, ErrInvalidThreshold
	}

	shares := make([]Share, n)
	for i := 0; i < n; i++ {
		shares[i] = Share{
			Index: i + 1,
			Data:  make([]byte, len(secret)),
		}
	}

	for byteIdx, secretByte := range secret {
		// Generate random polynomial coefficients [c_1, ..., c_{k-1}]
		poly := make([]byte, k)
		poly[0] = secretByte
		if _, err := rand.Read(poly[1:]); err != nil {
			return nil, fmt.Errorf("failed to generate random polynomial: %w", err)
		}

		// Evaluate polynomial at points x = 1, ..., n
		for i := 0; i < n; i++ {
			x := byte(i + 1)
			var y byte
			for exp := k - 1; exp >= 0; exp-- {
				y = gfMul(y, x) ^ poly[exp]
			}
			shares[i].Data[byteIdx] = y
		}
	}

	return shares, nil
}

// CombineShares reconstructs the original secret from any k valid shares using Lagrange interpolation.
func CombineShares(shares []Share, k int) ([]byte, error) {
	if len(shares) < k {
		return nil, ErrNotEnoughShares
	}

	sharesToUse := shares[:k]
	secretLen := len(sharesToUse[0].Data)
	secret := make([]byte, secretLen)

	// Lagrange basis interpolation at x = 0:
	// secret = sum_{j=0}^{k-1} ( y_j * prod_{m != j} (0 - x_m) / (x_j - x_m) )
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var secretByte byte
		for j := 0; j < k; j++ {
			xj := byte(sharesToUse[j].Index)
			yj := sharesToUse[j].Data[byteIdx]

			var num byte = 1
			var den byte = 1
			for m := 0; m < k; m++ {
				if m == j {
					continue
				}
				xm := byte(sharesToUse[m].Index)
				// (0 - xm) in GF(256) is xm because addition is XOR
				num = gfMul(num, xm)
				// (xj - xm) in GF(256) is xj ^ xm
				den = gfMul(den, xj^xm)
			}

			lagrange := gfMul(yj, gfDiv(num, den))
			secretByte ^= lagrange
		}
		secret[byteIdx] = secretByte
	}

	return secret, nil
}
