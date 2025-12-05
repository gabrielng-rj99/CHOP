package utils

import "testing"

func TestNormalizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Basic ASCII", "Hello World", "hello world"},
		{"Portuguese Accents", "João Ninguém", "joao ninguem"},
		{"Spanish Accents", "Mañana", "manana"},
		{"French Accents", "Café", "cafe"},
		{"Mixed Case", "Mixed CASE", "mixed case"},
		{"Empty String", "", ""},
		{"Numbers", "123", "123"},
		{"Special Chars", "Foo-Bar!", "foo-bar!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeString(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeString(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
