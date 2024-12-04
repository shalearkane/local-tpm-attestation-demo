package main

import (
	"fmt"
	"log"
	"os"

	"encoding/json"
	"github.com/google/go-attestation/attest"
)

func main() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening the TPM: %v\n", err)
		os.Exit(1)
	}

	createAK(tpm)
	ak := getAK(tpm)
	selftestAttest(tpm, ak)
	tpm.Close()
}

func createAK(tpm *attest.TPM) {
	k, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatalf("failed to mint an AK: %v", err)
	}
	defer k.Close(tpm)
	b, err := k.Marshal()
	if err != nil {
		log.Fatalf("failed to marshal AK: %v", err)
	}
	os.WriteFile("ak.json", b, 0644)
}

func getAK(tpm *attest.TPM) *attest.AK {
	b, err := os.ReadFile("ak.json")
	if err != nil {
		log.Fatalf("Could not load Key: %v\n", err)
	}
	k, _ := tpm.LoadAK(b)

	return k
}

// func

func selftestAttest(tpm *attest.TPM, ak *attest.AK) error {
	// This nonce is used in generating the quote. As this is a selftest,
	// it's set to an arbitrary value.
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	pub, err := attest.ParseAKPublic(tpm.Version(), ak.AttestationParameters().Public)
	if err != nil {
		return fmt.Errorf("failed to parse ak public: %v", err)
	}

	if _, err := tpm.MeasurementLog(); err != nil {
		return fmt.Errorf("no event log available: %v", err)
	}
	attestation, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		return fmt.Errorf("failed to attest: %v", err)
	}

	marshaledJSON, _ := json.MarshalIndent(attestation, "", "  ")
	os.WriteFile("at.json", marshaledJSON, 0644)

	for i, quote := range attestation.Quotes {
		if err := pub.Verify(quote, attestation.PCRs, nonce); err != nil {
			return fmt.Errorf("failed to verify quote[%d]: %v", i, err)
		}
	}

	el, err := attest.ParseEventLog(attestation.EventLog)
	if err != nil {
		return fmt.Errorf("failed to parse event log: %v", err)
	}

	if _, err := el.Verify(attestation.PCRs); err != nil {
		return fmt.Errorf("event log failed to verify: %v", err)
	}
	return nil
}
