package store

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// TestIsValidCPF exposes the private isValidCPF function for testing purposes
// It handles formatting cleanup internally
func TestIsValidCPF(cpf string) bool {
	// Clean up formatting
	cpf = strings.ReplaceAll(cpf, ".", "")
	cpf = strings.ReplaceAll(cpf, "-", "")
	cpf = strings.ReplaceAll(cpf, "/", "")
	cpf = strings.TrimSpace(cpf)

	return isValidCPF(cpf)
}

// TestIsValidCNPJ exposes the private isValidCNPJ function for testing purposes
// It handles formatting cleanup internally
func TestIsValidCNPJ(cnpj string) bool {
	// Clean up formatting
	cnpj = strings.ReplaceAll(cnpj, ".", "")
	cnpj = strings.ReplaceAll(cnpj, "-", "")
	cnpj = strings.ReplaceAll(cnpj, "/", "")
	cnpj = strings.TrimSpace(cnpj)

	return isValidCNPJ(cnpj)
}

// TestIsValidCPFOrCNPJ exposes the private isValidCPFOrCNPJ function for testing purposes
func TestIsValidCPFOrCNPJ(id string) bool {
	return isValidCPFOrCNPJ(id)
}

// TestCompareHashAndPassword exposes bcrypt comparison for testing purposes
func TestCompareHashAndPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
