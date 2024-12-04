package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"net/http"
	"os"

	"github.com/gin-gonic/gin"
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

func getAK(tpm *attest.TPM) *attest.AK {
	b, err := os.ReadFile("../ak.json")
	if err != nil {
		log.Fatalf("Could not load Key: %v\n", err)
	}
	k, _ := tpm.LoadAK(b)

	return k
}

func main() {
	router := gin.Default()

	router.POST("/verify", func(c *gin.Context) {
		// fileHash, _ := computeFileHash("../client/client.go")
		fileHash, _ := computeFileHash("server.go")
		nonce := fileHash

		attestation := attest.PlatformParameters{}
		tpm, _ := attest.OpenTPM(nil)
		ak := getAK(tpm)

		// Validate JSON input
		if err := c.ShouldBindJSON(&attestation); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		pub, err := attest.ParseAKPublic(2, ak.AttestationParameters().Public)
		if err != nil {
			fmt.Printf("failed to parse ak public: %v", err)
		}

		for i, quote := range attestation.Quotes {
			if err := pub.Verify(quote, attestation.PCRs, nonce); err != nil {
				fmt.Printf("failed to verify quote[%d]: %v", i, err)
				c.JSON(http.StatusBadRequest, gin.H{
					"message": "Client Verification failed",
					"quote":   quote,
				})
			} else {
				// Respond with the received data
				c.JSON(http.StatusOK, gin.H{
					"message": "Client Verified",
					"data":    attestation,
				})
			}
		}

	})

	// Define a wildcard route (404 handler)
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Route not found",
		})
	})

	// Start the server on port 8080
	router.Run(":8080")
}
