/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package repository

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ValidateStrongPassword validates password strength with minimum length
func ValidateStrongPassword(password string, minLength int) error {
	if len(password) < minLength {
		return fmt.Errorf("a senha deve ter pelo menos %d caracteres", minLength)
	}
	if strings.Contains(password, " ") {
		return errors.New("a senha não pode conter espaços")
	}
	reNumber := regexp.MustCompile(`[0-9]`)
	reLower := regexp.MustCompile(`[a-z]`)
	reUpper := regexp.MustCompile(`[A-Z]`)
	reSymbol := regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':",\.<>\/\?\\|]`)

	if !reNumber.MatchString(password) {
		return errors.New("a senha deve conter pelo menos um número")
	}
	if !reLower.MatchString(password) {
		return errors.New("a senha deve conter pelo menos uma letra minúscula")
	}
	if !reUpper.MatchString(password) {
		return errors.New("a senha deve conter pelo menos uma letra maiúscula")
	}
	if !reSymbol.MatchString(password) {
		return errors.New("a senha deve conter pelo menos um símbolo")
	}
	return nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// NormalizeOptionalString converts empty or whitespace-only strings to nil
func NormalizeOptionalString(s *string) *string {
	if s == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*s)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// ValidateName validates a name by trimming whitespace, checking it's not empty, and validating length
func ValidateName(name string, maxLength int) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("name cannot be empty or contain only whitespace")
	}
	if len(trimmed) > maxLength {
		return "", fmt.Errorf("name cannot exceed %d characters", maxLength)
	}
	return trimmed, nil
}

// ValidateUsername validates a username for proper format
// Requirements: 3-255 chars, alphanumeric + underscore only, no spaces or special chars
func ValidateUsername(username string) error {
	trimmed := strings.TrimSpace(username)

	if trimmed == "" {
		return errors.New("username cannot be empty")
	}

	if len(trimmed) < 3 {
		return errors.New("username must be at least 3 characters")
	}

	if len(trimmed) > 255 {
		return errors.New("username cannot exceed 255 characters")
	}

	// Only allow alphanumeric and underscore
	validUsernamePattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validUsernamePattern.MatchString(trimmed) {
		return errors.New("username can only contain letters, numbers, and underscores")
	}

	return nil
}

// ValidateCPF exposes the private isValidCPF function for testing purposes
// It handles formatting cleanup internally
func ValidateCPF(cpf string) bool {
	// Clean up formatting
	cpf = strings.ReplaceAll(cpf, ".", "")
	cpf = strings.ReplaceAll(cpf, "-", "")
	cpf = strings.ReplaceAll(cpf, "/", "")
	cpf = strings.TrimSpace(cpf)

	return isValidCPF(cpf)
}

// ValidateCNPJ exposes the private isValidCNPJ function for testing purposes
// It handles formatting cleanup internally
func ValidateCNPJ(cnpj string) bool {
	// Clean up formatting
	cnpj = strings.ReplaceAll(cnpj, ".", "")
	cnpj = strings.ReplaceAll(cnpj, "-", "")
	cnpj = strings.ReplaceAll(cnpj, "/", "")
	cnpj = strings.TrimSpace(cnpj)

	return isValidCNPJ(cnpj)
}

// ValidateCPFOrCNPJ exposes the private isValidCPFOrCNPJ function for testing purposes
func ValidateCPFOrCNPJ(id string) bool {
	return isValidCPFOrCNPJ(id)
}

// CompareHashAndPassword exposes bcrypt comparison for testing purposes
func CompareHashAndPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// FormatCPFOrCNPJ formats a CPF or CNPJ string to standard format
// CPF: 111.444.777-35
// CNPJ: 45.723.174/0001-10
func FormatCPFOrCNPJ(id string) (string, error) {
	// Remove all formatting
	clean := strings.ReplaceAll(id, ".", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, "/", "")
	clean = strings.TrimSpace(clean)

	// Check if it's valid
	if !isValidCPFOrCNPJ(id) {
		return "", errors.New("invalid CPF or CNPJ")
	}

	// Format based on length
	if len(clean) == 11 {
		// Format CPF: 111.444.777-35
		return fmt.Sprintf("%s.%s.%s-%s",
			clean[0:3], clean[3:6], clean[6:9], clean[9:11]), nil
	}
	if len(clean) == 14 {
		// Format CNPJ: 45.723.174/0001-10
		return fmt.Sprintf("%s.%s.%s/%s-%s",
			clean[0:2], clean[2:5], clean[5:8], clean[8:12], clean[12:14]), nil
	}

	return "", errors.New("invalid CPF or CNPJ length")
}
