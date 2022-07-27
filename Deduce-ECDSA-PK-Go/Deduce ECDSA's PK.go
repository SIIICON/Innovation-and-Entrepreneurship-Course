package main

// Taken from example here: https://stackoverflow.com/questions/51111605/how-do-i-recover-ecdsa-public-key-correctly-from-hashed-message-and-signature-in
import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func main() {

	argCount := len(os.Args[1:])

	msg := "hello"
	if argCount > 0 {
		msg = os.Args[1]
	}

	data := []byte(msg)

	getAddr, _ := randomHex(32)

	privateKey, _ := crypto.HexToECDSA(getAddr)
	fmt.Printf("Private key: %s\n", getAddr)
	fmt.Printf("Message to sign: %s\n", msg)

	publicKey := privateKey.PublicKey

	publicKeyBytes := crypto.FromECDSAPub(&publicKey)

	hash := crypto.Keccak256Hash(data)
	fmt.Printf("Hash: %x\n", hash.Bytes())

	fmt.Printf("\n=== Now using Ecrecover ===\n")
	signature, _ := crypto.Sign(hash.Bytes(), privateKey)

	fmt.Printf("ECDSA Signature: %x\n", signature)
	fmt.Printf("  R: %x\n", signature[0:32]) // 32 bytes
	fmt.Printf("  S: %x\n", signature[32:64]) // 32 bytes
	fmt.Printf("  V: %x\n", signature[64:])

	sigPublicKey, _ := crypto.Ecrecover(hash.Bytes(), signature)

	fmt.Printf("\nOriginal public key: %x\n", publicKeyBytes)
	fmt.Printf("Recovered public key: %x\n", sigPublicKey)

	rtn := bytes.Equal(sigPublicKey, publicKeyBytes)

	if rtn {
		fmt.Printf("Public keys match\n\n")
	}

	fmt.Printf("\n=== Now using FromECDSAPub ===\n")
	sigPublicKeyECDSA, _ := crypto.SigToPub(hash.Bytes(), signature)

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	rtn = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)

	fmt.Printf("Original public key: %x\n", publicKeyBytes)
	fmt.Printf("Recovered public key: %x\n", sigPublicKeyBytes)

	if rtn {
		fmt.Printf("Public keys match\n\n")
	}

	signatureNoRecoverID := signature[:len(signature)-1]
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	fmt.Println(verified)
}