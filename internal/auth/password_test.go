package auth

import (
	"testing"
)

func TestArgon2idPasswordHashing(t *testing.T) {
	password := "correct-horse-battery-staple-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}

	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Fatal("expected valid password verification")
	}

	invalid, err := VerifyPassword("wrong-password-12345", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if invalid {
		t.Fatal("expected invalid password verification to fail")
	}
}

func TestPasswordLengthPolicy(t *testing.T) {
	shortPass := "short123"
	_, err := HashPassword(shortPass)
	if err == nil {
		t.Fatal("expected error for password < 12 characters")
	}
}
