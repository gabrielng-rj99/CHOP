/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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

package main

import "testing"

func TestNormalizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase without accents",
			input:    "joao",
			expected: "joao",
		},
		{
			name:     "uppercase without accents",
			input:    "JOAO",
			expected: "joao",
		},
		{
			name:     "mixed case without accents",
			input:    "JoAo",
			expected: "joao",
		},
		{
			name:     "lowercase with accents",
			input:    "joão",
			expected: "joao",
		},
		{
			name:     "uppercase with accents",
			input:    "JOÃO",
			expected: "joao",
		},
		{
			name:     "mixed case with accents",
			input:    "João",
			expected: "joao",
		},
		{
			name:     "name with multiple accents",
			input:    "José María",
			expected: "jose maria",
		},
		{
			name:     "portuguese special characters",
			input:    "São Paulo - Ação",
			expected: "sao paulo - acao",
		},
		{
			name:     "café example",
			input:    "Café",
			expected: "cafe",
		},
		{
			name:     "address with accents",
			input:    "Rua José de Alencar, Edifício São João",
			expected: "rua jose de alencar, edificio sao joao",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "numbers and symbols",
			input:    "123-ABC",
			expected: "123-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeString(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeStringEquivalence(t *testing.T) {
	// Test that all variations of João produce the same normalized result
	variations := []string{"joão", "João", "JOÃO", "joao", "Joao", "JOAO"}
	expected := "joao"

	for _, v := range variations {
		result := normalizeString(v)
		if result != expected {
			t.Errorf("normalizeString(%q) = %q, want %q", v, result, expected)
		}
	}
}
