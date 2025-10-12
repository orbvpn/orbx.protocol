// internal/wireguard/keys.go

package wireguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func GenerateKeyPair() (privateKey, publicKey string, err error) {
	// Generate private key
	genCmd := exec.Command("wg", "genkey")
	privateKeyBytes, err := genCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey = strings.TrimSpace(string(privateKeyBytes))

	// Generate public key from private key
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = bytes.NewReader(privateKeyBytes)
	publicKeyBytes, err := pubCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey = strings.TrimSpace(string(publicKeyBytes))

	return privateKey, publicKey, nil
}

func GeneratePrivateKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func GetPublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
