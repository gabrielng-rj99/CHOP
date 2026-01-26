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

package userstore

import (
	"testing"
)

func TestValidateUserID(t *testing.T) {
	tests := []struct {
		name    string
		userID  string
		wantErr bool
	}{
		{
			name:    "valid UUID",
			userID:  "123e4567-e89b-12d3-a456-426614174000",
			wantErr: false,
		},
		{
			name:    "empty user ID",
			userID:  "",
			wantErr: true,
		},
		{
			name:    "invalid format - too short",
			userID:  "123e4567-e89b",
			wantErr: true,
		},
		{
			name:    "invalid format - no dashes",
			userID:  "123e4567e89b12d3a456426614174000",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			userID:  "123e4567-e89b-12d3-a456-42661417ZZZZ",
			wantErr: true,
		},
		{
			name:    "SQL injection attempt",
			userID:  "'; DROP TABLE users; --",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserID(tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUserID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateThemeMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{
			name:    "valid light mode",
			mode:    "light",
			wantErr: false,
		},
		{
			name:    "valid dark mode",
			mode:    "dark",
			wantErr: false,
		},
		{
			name:    "valid system mode",
			mode:    "system",
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mode:    "invalid",
			wantErr: true,
		},
		{
			name:    "empty mode",
			mode:    "",
			wantErr: true,
		},
		{
			name:    "uppercase mode",
			mode:    "DARK",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateThemeMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateThemeMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateColorBlindMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{
			name:    "valid none",
			mode:    "none",
			wantErr: false,
		},
		{
			name:    "valid protanopia",
			mode:    "protanopia",
			wantErr: false,
		},
		{
			name:    "valid deuteranopia",
			mode:    "deuteranopia",
			wantErr: false,
		},
		{
			name:    "valid tritanopia",
			mode:    "tritanopia",
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mode:    "invalid",
			wantErr: true,
		},
		{
			name:    "empty mode",
			mode:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateColorBlindMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateColorBlindMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateColor(t *testing.T) {
	validColor := "#ff0000"
	invalidColor := "red"
	emptyColor := ""
	shortHex := "#fff"
	longInvalid := "#fffffff"
	xssAttempt := "<script>alert(1)</script>"

	tests := []struct {
		name    string
		color   *string
		wantErr bool
	}{
		{
			name:    "valid 6-char hex color",
			color:   &validColor,
			wantErr: false,
		},
		{
			name:    "valid 3-char hex color",
			color:   &shortHex,
			wantErr: false,
		},
		{
			name:    "nil color",
			color:   nil,
			wantErr: false,
		},
		{
			name:    "empty string color",
			color:   &emptyColor,
			wantErr: false,
		},
		{
			name:    "invalid color name",
			color:   &invalidColor,
			wantErr: true,
		},
		{
			name:    "too long hex",
			color:   &longInvalid,
			wantErr: true,
		},
		{
			name:    "XSS attempt",
			color:   &xssAttempt,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateColor(tt.color)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateColor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePreset(t *testing.T) {
	tests := []struct {
		name    string
		preset  string
		wantErr bool
	}{
		{
			name:    "valid default preset",
			preset:  "default",
			wantErr: false,
		},
		{
			name:    "valid custom preset",
			preset:  "custom",
			wantErr: false,
		},
		{
			name:    "valid named theme",
			preset:  "ocean-blue",
			wantErr: false,
		},
		{
			name:    "SQL injection attempt",
			preset:  "'; DROP TABLE users; --",
			wantErr: true,
		},
		{
			name:    "script injection",
			preset:  "<script>alert(1)</script>",
			wantErr: true,
		},
		{
			name:    "javascript URI",
			preset:  "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "too long preset name",
			preset:  "this-is-a-very-long-preset-name-that-exceeds-the-maximum-allowed-length-for-theme-preset-names-in-the-system-and-should-fail-validation",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePreset(tt.preset)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePreset() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "string with leading/trailing spaces",
			input:    "  hello  ",
			expected: "hello",
		},
		{
			name:     "string with null byte",
			input:    "hello\x00world",
			expected: "helloworld",
		},
		{
			name:     "string with tabs",
			input:    "hello\tworld",
			expected: "hello\tworld",
		},
		{
			name:     "string with newlines",
			input:    "hello\nworld",
			expected: "hello\nworld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateUserThemeSettings(t *testing.T) {
	validUserID := "123e4567-e89b-12d3-a456-426614174000"
	validColor := "#ff0000"

	tests := []struct {
		name     string
		settings *UserThemeSettings
		wantErr  bool
	}{
		{
			name:     "nil settings",
			settings: nil,
			wantErr:  true,
		},
		{
			name: "valid settings",
			settings: &UserThemeSettings{
				UserID:         validUserID,
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: false,
		},
		{
			name: "valid settings with colors",
			settings: &UserThemeSettings{
				UserID:         validUserID,
				ThemePreset:    "custom",
				ThemeMode:      "light",
				ColorBlindMode: "none",
				PrimaryColor:   &validColor,
			},
			wantErr: false,
		},
		{
			name: "invalid user ID",
			settings: &UserThemeSettings{
				UserID:         "invalid",
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "invalid theme mode",
			settings: &UserThemeSettings{
				UserID:         validUserID,
				ThemePreset:    "default",
				ThemeMode:      "invalid",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "invalid colorblind mode",
			settings: &UserThemeSettings{
				UserID:         validUserID,
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserThemeSettings(tt.settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUserThemeSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecurityValidation(t *testing.T) {
	validUserID := "123e4567-e89b-12d3-a456-426614174000"

	// Test various injection attempts
	injectionAttempts := []string{
		"'; DROP TABLE users; --",
		"<script>alert('xss')</script>",
		"javascript:void(0)",
		"onclick=alert(1)",
		"SELECT * FROM users",
		"UNION SELECT password FROM users",
		"eval('malicious code')",
	}

	for _, injection := range injectionAttempts {
		t.Run("injection_in_preset_"+injection[:10], func(t *testing.T) {
			settings := &UserThemeSettings{
				UserID:         validUserID,
				ThemePreset:    injection,
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			}
			err := ValidateUserThemeSettings(settings)
			if err == nil {
				t.Errorf("ValidateUserThemeSettings() should reject injection: %s", injection)
			}
		})
	}
}

func TestHexColorRegex(t *testing.T) {
	validColors := []string{
		"#fff",
		"#FFF",
		"#000",
		"#123",
		"#abc",
		"#ABC",
		"#ffffff",
		"#FFFFFF",
		"#000000",
		"#123456",
		"#abcdef",
		"#ABCDEF",
		"#a1b2c3",
	}

	invalidColors := []string{
		"fff",
		"#ff",
		"#ffff",
		"#fffff",
		"#fffffff",
		"#ggg",
		"#GGGGGG",
		"red",
		"rgb(255,0,0)",
		"rgba(255,0,0,1)",
		"hsl(0,100%,50%)",
	}

	for _, color := range validColors {
		t.Run("valid_"+color, func(t *testing.T) {
			if !hexColorRegex.MatchString(color) {
				t.Errorf("hexColorRegex should match %s", color)
			}
		})
	}

	for _, color := range invalidColors {
		t.Run("invalid_"+color, func(t *testing.T) {
			if hexColorRegex.MatchString(color) {
				t.Errorf("hexColorRegex should not match %s", color)
			}
		})
	}
}
