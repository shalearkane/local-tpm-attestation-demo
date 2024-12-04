package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/google/go-attestation/attest"
)

// computeFileHash computes the SHA-256 hash of the specified file.
func computeFileHash(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}
	return hasher.Sum(nil), nil
}

func main() {
	// Base URL of the server
	baseURL := "http://localhost:8080"

	// Make a POST request
	err := testAttestation(baseURL + "/verify")
	if err != nil {
		log.Fatalf("POST request failed: %v", err)
	}
}

func getAK(tpm *attest.TPM) *attest.AK {
	b, err := os.ReadFile("../ak.json")
	if err != nil {
		log.Fatalf("Could not load Key: %v\n", err)
	}
	k, _ := tpm.LoadAK(b)

	return k
}

func testAttestation(url string) error {
	fileHash, _ := computeFileHash("client.go")
	tpm, _ := attest.OpenTPM(nil)
	ak := getAK(tpm)
	nonce := fileHash

	attestation, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		return fmt.Errorf("failed to attest: %v", err)
	}

	jsonData, err := json.Marshal(attestation)
	if err != nil {
		return fmt.Errorf("error marshaling data to JSON: %w", err)
	}

	tpm.Close()

	// Send the POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error making POST request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	// Print the response
	fmt.Printf("POST Response:\nStatus: %s\nBody: %s\n", resp.Status, string(body))
	return nil
}
