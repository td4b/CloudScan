package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Plaintext password
	password := "Huckjam17!"

	// Generate bcrypt hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error generating hash: %v", err)
	}

	// Print hashed password
	fmt.Println("Bcrypt hash:", string(hash))
}
