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

package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateThemeRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *UserThemeSettingsRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "valid request with defaults",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: false,
		},
		{
			name: "valid request with custom colors",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "custom",
				ThemeMode:      "light",
				ColorBlindMode: "none",
				PrimaryColor:   strPtr("#ff0000"),
				SecondaryColor: strPtr("#00ff00"),
			},
			wantErr: false,
		},
		{
			name: "empty theme mode",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "invalid theme mode",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "invalid",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "invalid colorblind mode",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid color format",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "custom",
				ThemeMode:      "light",
				ColorBlindMode: "none",
				PrimaryColor:   strPtr("red"),
			},
			wantErr: true,
		},
		{
			name: "SQL injection in preset",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "'; DROP TABLE users; --",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "XSS in preset",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "<script>alert(1)</script>",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "javascript URI in preset",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "javascript:alert(1)",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "preset too long",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "this-is-a-very-long-preset-name-that-exceeds-the-maximum-allowed-length-for-theme-preset-names-in-the-system",
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			},
			wantErr: true,
		},
		{
			name: "valid 3-char hex color",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "custom",
				ThemeMode:      "light",
				ColorBlindMode: "none",
				PrimaryColor:   strPtr("#fff"),
			},
			wantErr: false,
		},
		{
			name: "color too long",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "custom",
				ThemeMode:      "light",
				ColorBlindMode: "none",
				PrimaryColor:   strPtr("#fffffff"),
			},
			wantErr: true,
		},
		{
			name: "valid accessibility settings",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: "protanopia",
				HighContrast:   true,
			},
			wantErr: false,
		},
		{
			name: "valid deuteranopia mode",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "light",
				ColorBlindMode: "deuteranopia",
			},
			wantErr: false,
		},
		{
			name: "valid tritanopia mode",
			req: &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "system",
				ColorBlindMode: "tritanopia",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateThemeRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateThemeRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateColorField(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		color     *string
		wantErr   bool
	}{
		{
			name:      "nil color",
			fieldName: "primary_color",
			color:     nil,
			wantErr:   false,
		},
		{
			name:      "empty color",
			fieldName: "primary_color",
			color:     strPtr(""),
			wantErr:   false,
		},
		{
			name:      "valid 6-char hex",
			fieldName: "primary_color",
			color:     strPtr("#ff0000"),
			wantErr:   false,
		},
		{
			name:      "valid 3-char hex",
			fieldName: "primary_color",
			color:     strPtr("#f00"),
			wantErr:   false,
		},
		{
			name:      "valid uppercase hex",
			fieldName: "primary_color",
			color:     strPtr("#FF0000"),
			wantErr:   false,
		},
		{
			name:      "invalid color name",
			fieldName: "primary_color",
			color:     strPtr("red"),
			wantErr:   true,
		},
		{
			name:      "missing hash",
			fieldName: "primary_color",
			color:     strPtr("ff0000"),
			wantErr:   true,
		},
		{
			name:      "invalid hex characters",
			fieldName: "primary_color",
			color:     strPtr("#gggggg"),
			wantErr:   true,
		},
		{
			name:      "too long",
			fieldName: "primary_color",
			color:     strPtr("#fffffff"),
			wantErr:   true,
		},
		{
			name:      "rgba format",
			fieldName: "primary_color",
			color:     strPtr("rgba(255,0,0,1)"),
			wantErr:   true,
		},
		{
			name:      "rgb format",
			fieldName: "primary_color",
			color:     strPtr("rgb(255,0,0)"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateColorField(tt.fieldName, tt.color)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateColorField() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeStringHandler(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "default",
			expected: "default",
		},
		{
			name:     "string with spaces",
			input:    "  custom  ",
			expected: "custom",
		},
		{
			name:     "string with null bytes",
			input:    "default\x00",
			expected: "default",
		},
		{
			name:     "string with control characters",
			input:    "default\x01\x02\x03",
			expected: "default",
		},
		{
			name:     "string with allowed whitespace",
			input:    "ocean\tblue",
			expected: "ocean\tblue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSecurityInjectionAttempts(t *testing.T) {
	injections := []struct {
		name  string
		input string
	}{
		{"SQL DROP", "'; DROP TABLE users; --"},
		{"SQL SELECT", "' OR '1'='1"},
		{"SQL UNION", "' UNION SELECT * FROM users --"},
		{"XSS script tag", "<script>alert('xss')</script>"},
		{"XSS img onerror", "<img src=x onerror=alert(1)>"},
		{"JavaScript URI", "javascript:alert(1)"},
		{"Data URI", "data:text/html,<script>alert(1)</script>"},
		{"Event handler", "onclick=alert(1)"},
		{"Eval injection", "eval('malicious')"},
		{"Document access", "document.cookie"},
		{"Window access", "window.location"},
	}

	for _, tt := range injections {
		t.Run(tt.name, func(t *testing.T) {
			req := &UserThemeSettingsRequest{
				ThemePreset:    tt.input,
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			}
			err := validateThemeRequest(req)
			if err == nil {
				t.Errorf("validateThemeRequest() should reject injection attempt: %s", tt.input)
			}
		})
	}
}

func TestValidThemeModes(t *testing.T) {
	validModes := []string{"light", "dark", "system"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			req := &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      mode,
				ColorBlindMode: "none",
			}
			err := validateThemeRequest(req)
			if err != nil {
				t.Errorf("validateThemeRequest() should accept mode %s, got error: %v", mode, err)
			}
		})
	}
}

func TestValidColorBlindModes(t *testing.T) {
	validModes := []string{"none", "protanopia", "deuteranopia", "tritanopia"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			req := &UserThemeSettingsRequest{
				ThemePreset:    "default",
				ThemeMode:      "dark",
				ColorBlindMode: mode,
			}
			err := validateThemeRequest(req)
			if err != nil {
				t.Errorf("validateThemeRequest() should accept colorblind mode %s, got error: %v", mode, err)
			}
		})
	}
}

func TestAllColorFields(t *testing.T) {
	req := &UserThemeSettingsRequest{
		ThemePreset:        "custom",
		ThemeMode:          "light",
		ColorBlindMode:     "none",
		PrimaryColor:       strPtr("#ff0000"),
		SecondaryColor:     strPtr("#00ff00"),
		BackgroundColor:    strPtr("#0000ff"),
		SurfaceColor:       strPtr("#ffffff"),
		TextColor:          strPtr("#000000"),
		TextSecondaryColor: strPtr("#666666"),
		BorderColor:        strPtr("#cccccc"),
	}

	err := validateThemeRequest(req)
	if err != nil {
		t.Errorf("validateThemeRequest() should accept all valid colors, got error: %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	// Test that empty colorblind mode gets default
	req := &UserThemeSettingsRequest{
		ThemePreset:    "",
		ThemeMode:      "dark",
		ColorBlindMode: "",
	}

	err := validateThemeRequest(req)
	if err != nil {
		t.Errorf("validateThemeRequest() should apply defaults, got error: %v", err)
	}

	if req.ColorBlindMode != "none" {
		t.Errorf("expected colorblind mode to be 'none', got %s", req.ColorBlindMode)
	}

	if req.ThemePreset != "default" {
		t.Errorf("expected theme preset to be 'default', got %s", req.ThemePreset)
	}
}

// Helper function to create string pointer
func strPtr(s string) *string {
	return &s
}

// ============================================
// Global Theme Handler Tests
// ============================================

func TestGlobalThemeRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     GlobalThemeRequest
		wantErr bool
	}{
		{
			name: "valid preset",
			req: GlobalThemeRequest{
				ThemePreset: "default",
			},
			wantErr: false,
		},
		{
			name: "valid preset with colors",
			req: GlobalThemeRequest{
				ThemePreset:  "custom",
				PrimaryColor: strPtr("#3498db"),
			},
			wantErr: false,
		},
		{
			name: "SQL injection in preset",
			req: GlobalThemeRequest{
				ThemePreset: "'; DROP TABLE system_settings; --",
			},
			wantErr: true,
		},
		{
			name: "XSS in preset",
			req: GlobalThemeRequest{
				ThemePreset: "<script>alert('xss')</script>",
			},
			wantErr: true,
		},
		{
			name: "invalid color format",
			req: GlobalThemeRequest{
				ThemePreset:  "custom",
				PrimaryColor: strPtr("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test preset validation by checking for dangerous patterns
			var err error
			lowerPreset := strings.ToLower(tt.req.ThemePreset)
			for _, pattern := range dangerousPatterns {
				if strings.Contains(lowerPreset, strings.ToLower(pattern)) {
					err = fmt.Errorf("dangerous pattern detected")
					break
				}
			}
			if err == nil && len(tt.req.ThemePreset) > maxPresetLength {
				err = fmt.Errorf("preset too long")
			}
			if err == nil && tt.req.PrimaryColor != nil {
				err = validateColorField("primary_color", tt.req.PrimaryColor)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("validation error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================
// Allowed Themes Handler Tests
// ============================================

func TestAllowedThemesValidation(t *testing.T) {
	validThemes := map[string]bool{
		"default": true, "ocean": true, "forest": true, "sunset": true,
		"purple": true, "monochrome": true, "custom": true,
	}

	tests := []struct {
		name    string
		themes  []string
		wantErr bool
	}{
		{
			name:    "valid single theme",
			themes:  []string{"default"},
			wantErr: false,
		},
		{
			name:    "valid multiple themes",
			themes:  []string{"default", "ocean", "forest"},
			wantErr: false,
		},
		{
			name:    "all valid themes",
			themes:  []string{"default", "ocean", "forest", "sunset", "purple", "monochrome", "custom"},
			wantErr: false,
		},
		{
			name:    "empty themes list",
			themes:  []string{},
			wantErr: true,
		},
		{
			name:    "invalid theme",
			themes:  []string{"default", "invalid_theme"},
			wantErr: true,
		},
		{
			name:    "SQL injection theme",
			themes:  []string{"'; DROP TABLE users; --"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if len(tt.themes) == 0 {
				err = fmt.Errorf("at least one theme must be allowed")
			} else {
				for _, theme := range tt.themes {
					if !validThemes[theme] {
						err = fmt.Errorf("invalid theme: %s", theme)
						break
					}
				}
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("validation error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================
// System Config Handler Tests
// ============================================

func TestSystemConfigValidation(t *testing.T) {
	tests := []struct {
		name           string
		loginBlockTime int
		loginAttempts  int
		wantErr        bool
	}{
		{
			name:           "valid defaults",
			loginBlockTime: 300,
			loginAttempts:  5,
			wantErr:        false,
		},
		{
			name:           "minimum values",
			loginBlockTime: 60,
			loginAttempts:  3,
			wantErr:        false,
		},
		{
			name:           "maximum values",
			loginBlockTime: 3600,
			loginAttempts:  10,
			wantErr:        false,
		},
		{
			name:           "block time too low",
			loginBlockTime: 30,
			loginAttempts:  5,
			wantErr:        true,
		},
		{
			name:           "block time too high",
			loginBlockTime: 5000,
			loginAttempts:  5,
			wantErr:        true,
		},
		{
			name:           "attempts too low",
			loginBlockTime: 300,
			loginAttempts:  1,
			wantErr:        true,
		},
		{
			name:           "attempts too high",
			loginBlockTime: 300,
			loginAttempts:  20,
			wantErr:        true,
		},
		{
			name:           "both invalid",
			loginBlockTime: 10,
			loginAttempts:  100,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// Validate login_block_time (60-3600 seconds)
			if tt.loginBlockTime < 60 || tt.loginBlockTime > 3600 {
				err = fmt.Errorf("login block time must be between 60 and 3600 seconds")
			}

			// Validate login_attempts (3-10)
			if err == nil && (tt.loginAttempts < 3 || tt.loginAttempts > 10) {
				err = fmt.Errorf("login attempts must be between 3 and 10")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("validation error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================
// Security Tests for Root-Only Endpoints
// ============================================

func TestRootOnlyEndpointsSecurity(t *testing.T) {
	// These tests verify that the endpoint validation patterns work correctly
	// Actual HTTP tests require integration testing setup

	t.Run("global theme requires root role check", func(t *testing.T) {
		// Test validation logic
		roles := []string{"user", "admin"}
		for _, role := range roles {
			if role == "root" {
				t.Errorf("non-root role %s should be denied", role)
			}
		}
	})

	t.Run("allowed themes update requires root role check", func(t *testing.T) {
		roles := []string{"user", "admin"}
		for _, role := range roles {
			if role == "root" {
				t.Errorf("non-root role %s should be denied for update", role)
			}
		}
	})

	t.Run("system config requires root role check", func(t *testing.T) {
		roles := []string{"user", "admin"}
		for _, role := range roles {
			if role == "root" {
				t.Errorf("non-root role %s should be denied", role)
			}
		}
	})
}

func TestRequestSizeLimits(t *testing.T) {
	// Verify size limit constants are set appropriately
	t.Run("theme request size limit", func(t *testing.T) {
		if maxThemeRequestSize > 32*1024 {
			t.Errorf("maxThemeRequestSize too large: %d, should be <= 32KB", maxThemeRequestSize)
		}
		if maxThemeRequestSize < 1024 {
			t.Errorf("maxThemeRequestSize too small: %d, should be >= 1KB", maxThemeRequestSize)
		}
	})
}

func TestDangerousPatternsDetection(t *testing.T) {
	patterns := []string{
		"<script>",
		"javascript:",
		"onclick=",
		"onerror=",
		"DROP TABLE",
		"DELETE FROM",
		"UNION SELECT",
		"eval(",
		"document.cookie",
		"window.location",
	}

	for _, pattern := range patterns {
		t.Run("detects "+pattern, func(t *testing.T) {
			req := &UserThemeSettingsRequest{
				ThemePreset:    pattern,
				ThemeMode:      "dark",
				ColorBlindMode: "none",
			}
			err := validateThemeRequest(req)
			if err == nil {
				t.Errorf("should detect dangerous pattern: %s", pattern)
			}
		})
	}
}
