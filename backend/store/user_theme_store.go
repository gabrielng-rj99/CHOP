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

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// UserThemeSettings represents a user's theme preferences
type UserThemeSettings struct {
	ID                 string    `json:"id"`
	UserID             string    `json:"user_id"`
	ThemePreset        string    `json:"theme_preset"`
	ThemeMode          string    `json:"theme_mode"`
	PrimaryColor       *string   `json:"primary_color,omitempty"`
	SecondaryColor     *string   `json:"secondary_color,omitempty"`
	BackgroundColor    *string   `json:"background_color,omitempty"`
	SurfaceColor       *string   `json:"surface_color,omitempty"`
	TextColor          *string   `json:"text_color,omitempty"`
	TextSecondaryColor *string   `json:"text_secondary_color,omitempty"`
	BorderColor        *string   `json:"border_color,omitempty"`
	HighContrast       bool      `json:"high_contrast"`
	ColorBlindMode     string    `json:"color_blind_mode"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// UserThemeStore manages user theme settings in the database
type UserThemeStore struct {
	db DBInterface
}

// NewUserThemeStore creates a new instance of UserThemeStore
func NewUserThemeStore(db DBInterface) *UserThemeStore {
	return &UserThemeStore{
		db: db,
	}
}

// Validation constants
const (
	MaxPresetLength      = 100
	MaxColorLength       = 7
	MaxColorBlindModeLen = 20
)

// Valid theme modes
var validThemeModes = map[string]bool{
	"light":  true,
	"dark":   true,
	"system": true,
}

// Valid colorblind modes
var validColorBlindModes = map[string]bool{
	"none":         true,
	"protanopia":   true,
	"deuteranopia": true,
	"tritanopia":   true,
}

// Hex color regex pattern
var hexColorRegex = regexp.MustCompile(`^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$`)

// Validation errors
var (
	ErrInvalidUserID         = errors.New("invalid user ID")
	ErrInvalidThemeMode      = errors.New("invalid theme mode: must be 'light', 'dark', or 'system'")
	ErrInvalidColorBlindMode = errors.New("invalid colorblind mode")
	ErrInvalidColorFormat    = errors.New("invalid color format: must be hex (#RGB or #RRGGBB)")
	ErrPresetTooLong         = errors.New("theme preset name too long")
	ErrPotentialInjection    = errors.New("potential injection detected in input")
)

// validateUserID checks if the user ID is a valid UUID format
func validateUserID(userID string) error {
	if userID == "" {
		return ErrInvalidUserID
	}
	// Basic UUID format validation (8-4-4-4-12)
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(userID) {
		return ErrInvalidUserID
	}
	return nil
}

// validateThemeMode checks if the theme mode is valid
func validateThemeMode(mode string) error {
	if !validThemeModes[mode] {
		return ErrInvalidThemeMode
	}
	return nil
}

// validateColorBlindMode checks if the colorblind mode is valid
func validateColorBlindMode(mode string) error {
	if !validColorBlindModes[mode] {
		return ErrInvalidColorBlindMode
	}
	return nil
}

// validateColor validates a hex color string
func validateColor(color *string) error {
	if color == nil || *color == "" {
		return nil // Optional colors are allowed to be nil/empty
	}
	if len(*color) > MaxColorLength {
		return ErrInvalidColorFormat
	}
	if !hexColorRegex.MatchString(*color) {
		return ErrInvalidColorFormat
	}
	return nil
}

// validatePreset validates the theme preset name
func validatePreset(preset string) error {
	if len(preset) > MaxPresetLength {
		return ErrPresetTooLong
	}
	// Check for potential SQL injection or XSS patterns
	dangerous := []string{
		// SQL injection patterns
		"<script", "javascript:", "onclick", "onerror", "onload", "onmouseover",
		"--", "/*", "*/", ";", "DROP ", "DELETE ", "INSERT ", "UPDATE ", "UNION ",
		"SELECT ", "EXEC ", "EXECUTE ", "xp_", "sp_", "INTO ", "FROM ", "WHERE ",
		// XSS and code injection patterns
		"eval(", "alert(", "document.", "window.", "console.", ".cookie",
		"String.fromCharCode", "atob(", "btoa(",
		// Other dangerous patterns
		"&#", "%3c", "%3e", "\\x", "\\u",
	}
	lowerPreset := strings.ToLower(preset)
	for _, pattern := range dangerous {
		if strings.Contains(lowerPreset, strings.ToLower(pattern)) {
			return ErrPotentialInjection
		}
	}
	return nil
}

// sanitizeString removes potentially dangerous characters from strings
func sanitizeString(s string) string {
	// Remove null bytes and control characters
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// ValidateUserThemeSettings validates all fields of UserThemeSettings
func ValidateUserThemeSettings(settings *UserThemeSettings) error {
	if settings == nil {
		return errors.New("settings cannot be nil")
	}

	if err := validateUserID(settings.UserID); err != nil {
		return err
	}

	if err := validateThemeMode(settings.ThemeMode); err != nil {
		return err
	}

	if err := validateColorBlindMode(settings.ColorBlindMode); err != nil {
		return err
	}

	if err := validatePreset(settings.ThemePreset); err != nil {
		return err
	}

	// Validate all color fields
	colorFields := []*string{
		settings.PrimaryColor,
		settings.SecondaryColor,
		settings.BackgroundColor,
		settings.SurfaceColor,
		settings.TextColor,
		settings.TextSecondaryColor,
		settings.BorderColor,
	}

	for _, color := range colorFields {
		if err := validateColor(color); err != nil {
			return err
		}
	}

	return nil
}

// GetUserThemeSettings retrieves theme settings for a specific user
func (s *UserThemeStore) GetUserThemeSettings(userID string) (*UserThemeSettings, error) {
	if err := validateUserID(userID); err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, theme_preset, theme_mode,
			   primary_color, secondary_color, background_color,
			   surface_color, text_color, text_secondary_color, border_color,
			   high_contrast, color_blind_mode, created_at, updated_at
		FROM user_theme_settings
		WHERE user_id = $1
	`

	var settings UserThemeSettings
	err := s.db.QueryRow(query, userID).Scan(
		&settings.ID,
		&settings.UserID,
		&settings.ThemePreset,
		&settings.ThemeMode,
		&settings.PrimaryColor,
		&settings.SecondaryColor,
		&settings.BackgroundColor,
		&settings.SurfaceColor,
		&settings.TextColor,
		&settings.TextSecondaryColor,
		&settings.BorderColor,
		&settings.HighContrast,
		&settings.ColorBlindMode,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No settings found, return nil without error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user theme settings: %w", err)
	}

	return &settings, nil
}

// CreateUserThemeSettings creates new theme settings for a user
func (s *UserThemeStore) CreateUserThemeSettings(settings *UserThemeSettings) error {
	if err := ValidateUserThemeSettings(settings); err != nil {
		return err
	}

	// Sanitize string inputs
	settings.ThemePreset = sanitizeString(settings.ThemePreset)

	query := `
		INSERT INTO user_theme_settings (
			user_id, theme_preset, theme_mode,
			primary_color, secondary_color, background_color,
			surface_color, text_color, text_secondary_color, border_color,
			high_contrast, color_blind_mode, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`

	now := time.Now()
	err := s.db.QueryRow(
		query,
		settings.UserID,
		settings.ThemePreset,
		settings.ThemeMode,
		settings.PrimaryColor,
		settings.SecondaryColor,
		settings.BackgroundColor,
		settings.SurfaceColor,
		settings.TextColor,
		settings.TextSecondaryColor,
		settings.BorderColor,
		settings.HighContrast,
		settings.ColorBlindMode,
		now,
		now,
	).Scan(&settings.ID)

	if err != nil {
		return fmt.Errorf("failed to create user theme settings: %w", err)
	}

	settings.CreatedAt = now
	settings.UpdatedAt = now

	return nil
}

// UpdateUserThemeSettings updates existing theme settings for a user
func (s *UserThemeStore) UpdateUserThemeSettings(settings *UserThemeSettings) error {
	if err := ValidateUserThemeSettings(settings); err != nil {
		return err
	}

	// Sanitize string inputs
	settings.ThemePreset = sanitizeString(settings.ThemePreset)

	query := `
		UPDATE user_theme_settings SET
			theme_preset = $2,
			theme_mode = $3,
			primary_color = $4,
			secondary_color = $5,
			background_color = $6,
			surface_color = $7,
			text_color = $8,
			text_secondary_color = $9,
			border_color = $10,
			high_contrast = $11,
			color_blind_mode = $12,
			updated_at = $13
		WHERE user_id = $1
	`

	now := time.Now()
	result, err := s.db.Exec(
		query,
		settings.UserID,
		settings.ThemePreset,
		settings.ThemeMode,
		settings.PrimaryColor,
		settings.SecondaryColor,
		settings.BackgroundColor,
		settings.SurfaceColor,
		settings.TextColor,
		settings.TextSecondaryColor,
		settings.BorderColor,
		settings.HighContrast,
		settings.ColorBlindMode,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to update user theme settings: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// No existing record, create one
		return s.CreateUserThemeSettings(settings)
	}

	settings.UpdatedAt = now
	return nil
}

// UpsertUserThemeSettings creates or updates theme settings for a user
func (s *UserThemeStore) UpsertUserThemeSettings(settings *UserThemeSettings) error {
	if err := ValidateUserThemeSettings(settings); err != nil {
		return err
	}

	// Sanitize string inputs
	settings.ThemePreset = sanitizeString(settings.ThemePreset)

	query := `
		INSERT INTO user_theme_settings (
			user_id, theme_preset, theme_mode,
			primary_color, secondary_color, background_color,
			surface_color, text_color, text_secondary_color, border_color,
			high_contrast, color_blind_mode, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (user_id) DO UPDATE SET
			theme_preset = EXCLUDED.theme_preset,
			theme_mode = EXCLUDED.theme_mode,
			primary_color = EXCLUDED.primary_color,
			secondary_color = EXCLUDED.secondary_color,
			background_color = EXCLUDED.background_color,
			surface_color = EXCLUDED.surface_color,
			text_color = EXCLUDED.text_color,
			text_secondary_color = EXCLUDED.text_secondary_color,
			border_color = EXCLUDED.border_color,
			high_contrast = EXCLUDED.high_contrast,
			color_blind_mode = EXCLUDED.color_blind_mode,
			updated_at = EXCLUDED.updated_at
		RETURNING id, created_at
	`

	now := time.Now()
	err := s.db.QueryRow(
		query,
		settings.UserID,
		settings.ThemePreset,
		settings.ThemeMode,
		settings.PrimaryColor,
		settings.SecondaryColor,
		settings.BackgroundColor,
		settings.SurfaceColor,
		settings.TextColor,
		settings.TextSecondaryColor,
		settings.BorderColor,
		settings.HighContrast,
		settings.ColorBlindMode,
		now,
		now,
	).Scan(&settings.ID, &settings.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to upsert user theme settings: %w", err)
	}

	settings.UpdatedAt = now
	return nil
}

// DeleteUserThemeSettings removes theme settings for a user
func (s *UserThemeStore) DeleteUserThemeSettings(userID string) error {
	if err := validateUserID(userID); err != nil {
		return err
	}

	query := `DELETE FROM user_theme_settings WHERE user_id = $1`

	_, err := s.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user theme settings: %w", err)
	}

	return nil
}

// GetThemePermissions retrieves the theme permission settings
func (s *UserThemeStore) GetThemePermissions() (usersCanEdit bool, adminsCanEdit bool, err error) {
	// Get users permission
	var usersValue string
	err = s.db.QueryRow("SELECT value FROM system_settings WHERE key = $1", "permissions.users_can_edit_theme").Scan(&usersValue)
	if err != nil && err != sql.ErrNoRows {
		return false, false, fmt.Errorf("failed to get users theme permission: %w", err)
	}
	usersCanEdit = usersValue == "true"

	// Get admins permission
	var adminsValue string
	err = s.db.QueryRow("SELECT value FROM system_settings WHERE key = $1", "permissions.admins_can_edit_theme").Scan(&adminsValue)
	if err != nil && err != sql.ErrNoRows {
		return false, false, fmt.Errorf("failed to get admins theme permission: %w", err)
	}
	adminsCanEdit = adminsValue == "true"

	return usersCanEdit, adminsCanEdit, nil
}

// SetThemePermissions updates the theme permission settings (root only)
func (s *UserThemeStore) SetThemePermissions(usersCanEdit, adminsCanEdit bool) error {
	// Update users permission
	usersValue := "false"
	if usersCanEdit {
		usersValue = "true"
	}
	_, err := s.db.Exec(`
		INSERT INTO system_settings (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, "permissions.users_can_edit_theme", usersValue)
	if err != nil {
		return fmt.Errorf("failed to set users theme permission: %w", err)
	}

	// Update admins permission
	adminsValue := "false"
	if adminsCanEdit {
		adminsValue = "true"
	}
	_, err = s.db.Exec(`
		INSERT INTO system_settings (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, "permissions.admins_can_edit_theme", adminsValue)
	if err != nil {
		return fmt.Errorf("failed to set admins theme permission: %w", err)
	}

	return nil
}
