package store

import (
	"testing"
)

// TestIsValidCPF tests the CPF validation function with various inputs
func TestIsValidCPF(t *testing.T) {
	tests := []struct {
		name     string
		cpf      string
		expected bool
	}{
		// Valid CPFs
		{
			name:     "valid CPF - 11144477735",
			cpf:      "11144477735",
			expected: true,
		},
		{
			name:     "valid CPF with formatting",
			cpf:      "111.444.777-35",
			expected: true,
		},
		{
			name:     "valid CPF with dots and dashes",
			cpf:      "111.444.777-35",
			expected: true,
		},
		// Invalid CPFs - all same digits
		{
			name:     "invalid CPF - all zeros",
			cpf:      "00000000000",
			expected: false,
		},
		{
			name:     "invalid CPF - all ones",
			cpf:      "11111111111",
			expected: false,
		},
		{
			name:     "invalid CPF - all twos",
			cpf:      "22222222222",
			expected: false,
		},
		{
			name:     "invalid CPF - all threes",
			cpf:      "33333333333",
			expected: false,
		},
		{
			name:     "invalid CPF - all fours",
			cpf:      "44444444444",
			expected: false,
		},
		{
			name:     "invalid CPF - all fives",
			cpf:      "55555555555",
			expected: false,
		},
		{
			name:     "invalid CPF - all sixes",
			cpf:      "66666666666",
			expected: false,
		},
		{
			name:     "invalid CPF - all sevens",
			cpf:      "77777777777",
			expected: false,
		},
		{
			name:     "invalid CPF - all eights",
			cpf:      "88888888888",
			expected: false,
		},
		{
			name:     "invalid CPF - all nines",
			cpf:      "99999999999",
			expected: false,
		},
		// Invalid CPFs - wrong check digits
		{
			name:     "invalid CPF - wrong first check digit",
			cpf:      "11144477734",
			expected: false,
		},
		{
			name:     "invalid CPF - wrong second check digit",
			cpf:      "11144477736",
			expected: false,
		},
		// Invalid CPFs - wrong length
		{
			name:     "invalid CPF - too short",
			cpf:      "1114447773",
			expected: false,
		},
		{
			name:     "invalid CPF - too long",
			cpf:      "111444777355",
			expected: false,
		},
		{
			name:     "invalid CPF - empty",
			cpf:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCPF(tt.cpf)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for CPF: %s", tt.expected, result, tt.cpf)
			}
		})
	}
}

// TestIsValidCNPJ tests the CNPJ validation function with various inputs
func TestIsValidCNPJ(t *testing.T) {
	tests := []struct {
		name     string
		cnpj     string
		expected bool
	}{
		// Valid CNPJs
		{
			name:     "valid CNPJ - 45723174000110",
			cnpj:     "45723174000110",
			expected: true,
		},
		{
			name:     "valid CNPJ with formatting",
			cnpj:     "45.723.174/0001-10",
			expected: true,
		},
		{
			name:     "valid CNPJ - 11222333000181",
			cnpj:     "11222333000181",
			expected: true,
		},
		// Invalid CNPJs - all same digits
		{
			name:     "invalid CNPJ - all zeros",
			cnpj:     "00000000000000",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all ones",
			cnpj:     "11111111111111",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all twos",
			cnpj:     "22222222222222",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all threes",
			cnpj:     "33333333333333",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all fours",
			cnpj:     "44444444444444",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all fives",
			cnpj:     "55555555555555",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all sixes",
			cnpj:     "66666666666666",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all sevens",
			cnpj:     "77777777777777",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all eights",
			cnpj:     "88888888888888",
			expected: false,
		},
		{
			name:     "invalid CNPJ - all nines",
			cnpj:     "99999999999999",
			expected: false,
		},
		// Invalid CNPJs - wrong check digits
		{
			name:     "invalid CNPJ - wrong first check digit",
			cnpj:     "45723174000111",
			expected: false,
		},
		{
			name:     "invalid CNPJ - wrong second check digit",
			cnpj:     "45723174000109",
			expected: false,
		},
		// Invalid CNPJs - wrong length
		{
			name:     "invalid CNPJ - too short",
			cnpj:     "457231740001",
			expected: false,
		},
		{
			name:     "invalid CNPJ - too long",
			cnpj:     "457231740001101",
			expected: false,
		},
		{
			name:     "invalid CNPJ - empty",
			cnpj:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCNPJ(tt.cnpj)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for CNPJ: %s", tt.expected, result, tt.cnpj)
			}
		})
	}
}

// TestValidateStrongPassword tests password validation with various inputs
func TestValidateStrongPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
	}{
		// Valid passwords
		{
			name:        "valid password - 16 chars with all requirements",
			password:    "ValidPass123!@#a",
			expectError: false,
		},
		{
			name:        "valid password - 20 chars",
			password:    "ValidPassword123!@#ab",
			expectError: false,
		},
		{
			name:        "valid password - complex",
			password:    "C0mpl3x!Pwd@2024xyz",
			expectError: false,
		},
		// Invalid passwords - too short
		{
			name:        "invalid - too short (15 chars)",
			password:    "ValidPass123!@#",
			expectError: true,
			errorMsg:    "a senha deve ter pelo menos 16 caracteres",
		},
		{
			name:        "invalid - too short (10 chars)",
			password:    "ValidPass1!@",
			expectError: true,
			errorMsg:    "a senha deve ter pelo menos 16 caracteres",
		},
		// Invalid passwords - missing number
		{
			name:        "invalid - no number",
			password:    "ValidPassword!@#abc",
			expectError: true,
			errorMsg:    "a senha deve conter pelo menos um número",
		},
		// Invalid passwords - missing lowercase
		{
			name:        "invalid - no lowercase",
			password:    "VALIDPASSWORD123!@#",
			expectError: true,
			errorMsg:    "a senha deve conter pelo menos uma letra minúscula",
		},
		// Invalid passwords - missing uppercase
		{
			name:        "invalid - no uppercase",
			password:    "validpassword123!@#",
			expectError: true,
			errorMsg:    "a senha deve conter pelo menos uma letra maiúscula",
		},
		// Invalid passwords - missing symbol
		{
			name:        "invalid - no symbol",
			password:    "ValidPassword123abcd",
			expectError: true,
			errorMsg:    "a senha deve conter pelo menos um símbolo",
		},
		// Edge cases
		{
			name:        "valid - exactly 16 chars with all requirements",
			password:    "Pass1234!@#$%^&X",
			expectError: false,
		},
		{
			name:        "invalid - empty password",
			password:    "",
			expectError: true,
			errorMsg:    "a senha deve ter pelo menos 16 caracteres",
		},
		// Valid passwords with different symbols
		{
			name:        "valid - with various symbols",
			password:    "ValidPass123!(){}<>",
			expectError: false,
		},
		{
			name:        "valid - with underscore and dash",
			password:    "ValidPass123-_=+[]",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrongPassword(tt.password)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestHashPassword tests password hashing and verification
func TestHashPassword(t *testing.T) {
	password := "ValidPassword123!@#"

	// Hash the password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Hash should not be empty
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Hash should not equal the original password
	if hash == password {
		t.Error("hash should not equal the original password")
	}

	// Hash should be verifiable with bcrypt
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{
			name:     "correct password",
			password: "ValidPassword123!@#",
			valid:    true,
		},
		{
			name:     "wrong password",
			password: "WrongPassword123!@#",
			valid:    false,
		},
		{
			name:     "empty password",
			password: "",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareHashAndPassword(hash, tt.password)
			if result != tt.valid {
				t.Errorf("expected %v for password '%s', got %v", tt.valid, tt.password, result)
			}
		})
	}
}
