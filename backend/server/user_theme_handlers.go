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

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"Open-Generic-Hub/backend/store"
)

// Maximum request body size for theme settings (16KB should be more than enough)
const maxThemeRequestSize = 16 * 1024

// UserThemeSettingsRequest represents the incoming request for theme settings
type UserThemeSettingsRequest struct {
	ThemePreset        string  `json:"theme_preset"`
	ThemeMode          string  `json:"theme_mode"`
	PrimaryColor       *string `json:"primary_color,omitempty"`
	SecondaryColor     *string `json:"secondary_color,omitempty"`
	BackgroundColor    *string `json:"background_color,omitempty"`
	SurfaceColor       *string `json:"surface_color,omitempty"`
	TextColor          *string `json:"text_color,omitempty"`
	TextSecondaryColor *string `json:"text_secondary_color,omitempty"`
	BorderColor        *string `json:"border_color,omitempty"`
	HighContrast       bool    `json:"high_contrast"`
	ColorBlindMode     string  `json:"color_blind_mode"`
}

// ThemePermissionsRequest represents the request for updating theme permissions
type ThemePermissionsRequest struct {
	UsersCanEditTheme  bool `json:"users_can_edit_theme"`
	AdminsCanEditTheme bool `json:"admins_can_edit_theme"`
}

// ThemePermissionsResponse represents the response for theme permissions
type ThemePermissionsResponse struct {
	UsersCanEditTheme  bool `json:"users_can_edit_theme"`
	AdminsCanEditTheme bool `json:"admins_can_edit_theme"`
}

// Validation constants
const (
	maxPresetLength      = 100
	maxColorLength       = 7
	maxColorBlindModeLen = 20
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

// Dangerous patterns for injection detection
var dangerousPatterns = []string{
	"<script", "</script>", "javascript:", "onclick", "onerror", "onload",
	"--", "/*", "*/", ";;", "DROP ", "DELETE ", "INSERT ", "UPDATE ",
	"UNION ", "SELECT ", "EXEC ", "EXECUTE ", "xp_", "sp_",
	"eval(", "alert(", "document.", "window.",
}

// validateThemeRequest performs comprehensive validation on the theme request
func validateThemeRequest(req *UserThemeSettingsRequest) error {
	// Check for nil request
	if req == nil {
		return fmt.Errorf("request body is required")
	}

	// Validate theme mode
	if req.ThemeMode == "" {
		return fmt.Errorf("theme_mode is required")
	}
	if !validThemeModes[req.ThemeMode] {
		return fmt.Errorf("invalid theme_mode: must be 'light', 'dark', or 'system'")
	}

	// Validate colorblind mode
	if req.ColorBlindMode == "" {
		req.ColorBlindMode = "none" // Default value
	}
	if !validColorBlindModes[req.ColorBlindMode] {
		return fmt.Errorf("invalid color_blind_mode: must be 'none', 'protanopia', 'deuteranopia', or 'tritanopia'")
	}

	// Validate theme preset
	if req.ThemePreset == "" {
		req.ThemePreset = "default" // Default value
	}
	if len(req.ThemePreset) > maxPresetLength {
		return fmt.Errorf("theme_preset too long: maximum %d characters", maxPresetLength)
	}

	// Check for injection patterns in preset
	lowerPreset := strings.ToLower(req.ThemePreset)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPreset, strings.ToLower(pattern)) {
			log.Printf("🚨 SECURITY: Potential injection detected in theme_preset: %s", req.ThemePreset)
			return fmt.Errorf("invalid characters in theme_preset")
		}
	}

	// Validate color fields
	colorFields := map[string]*string{
		"primary_color":        req.PrimaryColor,
		"secondary_color":      req.SecondaryColor,
		"background_color":     req.BackgroundColor,
		"surface_color":        req.SurfaceColor,
		"text_color":           req.TextColor,
		"text_secondary_color": req.TextSecondaryColor,
		"border_color":         req.BorderColor,
	}

	for fieldName, color := range colorFields {
		if err := validateColorField(fieldName, color); err != nil {
			return err
		}
	}

	return nil
}

// validateColorField validates a single color field
func validateColorField(fieldName string, color *string) error {
	if color == nil || *color == "" {
		return nil // Optional field
	}

	// Check length
	if len(*color) > maxColorLength {
		return fmt.Errorf("%s too long: maximum %d characters", fieldName, maxColorLength)
	}

	// Validate hex format
	if !hexColorRegex.MatchString(*color) {
		return fmt.Errorf("invalid %s format: must be hex (#RGB or #RRGGBB)", fieldName)
	}

	return nil
}

// sanitizeString removes potentially dangerous characters
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

// HandleGetUserTheme handles GET /api/user/theme
// Returns the current user's theme settings
func (s *Server) HandleGetUserTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate database connection
	if s.userThemeStore == nil {
		log.Printf("❌ User theme store not initialized")
		respondError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		log.Printf("❌ Invalid token for user theme request: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Get user theme settings
	settings, err := s.userThemeStore.GetUserThemeSettings(claims.UserID)
	if err != nil {
		log.Printf("❌ Error getting user theme settings for user %s: %v", claims.UserID, err)
		respondError(w, http.StatusInternalServerError, "Erro ao obter configurações de tema")
		return
	}

	// If user has no theme, apply global theme
	if settings == nil {
		globalTheme := s.getGlobalThemeSettings()
		if globalTheme != nil {
			settings = globalTheme
			log.Printf("ℹ️ User %s has no custom theme, applying global theme: %s", claims.UserID, globalTheme.ThemePreset)
		}
	}

	// Get theme permissions
	usersCanEdit, adminsCanEdit, err := s.userThemeStore.GetThemePermissions()
	if err != nil {
		log.Printf("⚠️ Error getting theme permissions: %v", err)
		// Continue with default permissions (deny)
		usersCanEdit = false
		adminsCanEdit = true
	}

	// Determine if user can edit their theme
	canEdit := false
	switch claims.Role {
	case "root":
		canEdit = true
	case "admin":
		canEdit = adminsCanEdit
	case "user":
		canEdit = usersCanEdit
	}

	// Build response
	response := map[string]interface{}{
		"can_edit": canEdit,
		"permissions": ThemePermissionsResponse{
			UsersCanEditTheme:  usersCanEdit,
			AdminsCanEditTheme: adminsCanEdit,
		},
	}

	if settings != nil {
		response["settings"] = settings
	} else {
		// Return default settings if none exist
		response["settings"] = nil
	}

	respondJSON(w, http.StatusOK, response)
}

// HandleUpdateUserTheme handles PUT /api/user/theme
// Updates the current user's theme settings
func (s *Server) HandleUpdateUserTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate database connection
	if s.userThemeStore == nil {
		log.Printf("❌ User theme store not initialized")
		respondError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		log.Printf("❌ Invalid token for user theme update: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Check permissions
	usersCanEdit, adminsCanEdit, err := s.userThemeStore.GetThemePermissions()
	if err != nil {
		log.Printf("⚠️ Error getting theme permissions: %v", err)
		usersCanEdit = false
		adminsCanEdit = true
	}

	canEdit := false
	switch claims.Role {
	case "root":
		canEdit = true
	case "admin":
		canEdit = adminsCanEdit
	case "user":
		canEdit = usersCanEdit
	}

	if !canEdit {
		log.Printf("🚫 User %s (role: %s) denied permission to edit theme", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Você não tem permissão para alterar configurações de tema")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxThemeRequestSize)

	// Parse request body
	var req UserThemeSettingsRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Reject unknown fields for security
	if err := decoder.Decode(&req); err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			log.Printf("🚨 SECURITY: Request body too large from user %s", claims.Username)
			respondError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		log.Printf("❌ Invalid request body from user %s: %v", claims.Username, err)
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := validateThemeRequest(&req); err != nil {
		log.Printf("❌ Invalid theme request from user %s: %v", claims.Username, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Sanitize string inputs
	req.ThemePreset = sanitizeString(req.ThemePreset)
	req.ThemeMode = sanitizeString(req.ThemeMode)
	req.ColorBlindMode = sanitizeString(req.ColorBlindMode)

	// Build settings object
	settings := &store.UserThemeSettings{
		UserID:             claims.UserID,
		ThemePreset:        req.ThemePreset,
		ThemeMode:          req.ThemeMode,
		PrimaryColor:       req.PrimaryColor,
		SecondaryColor:     req.SecondaryColor,
		BackgroundColor:    req.BackgroundColor,
		SurfaceColor:       req.SurfaceColor,
		TextColor:          req.TextColor,
		TextSecondaryColor: req.TextSecondaryColor,
		BorderColor:        req.BorderColor,
		HighContrast:       req.HighContrast,
		ColorBlindMode:     req.ColorBlindMode,
	}

	// Upsert settings
	if err := s.userThemeStore.UpsertUserThemeSettings(settings); err != nil {
		log.Printf("❌ Error saving user theme settings for user %s: %v", claims.Username, err)
		respondError(w, http.StatusInternalServerError, "Erro ao salvar configurações de tema")
		return
	}

	log.Printf("✅ User %s updated theme settings (preset: %s, mode: %s)", claims.Username, req.ThemePreset, req.ThemeMode)

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Configurações de tema salvas com sucesso",
		Data:    settings,
	})
}

// HandleGetThemePermissions handles GET /api/settings/theme-permissions
// Returns the current theme permission settings (root only)
func (s *Server) HandleGetThemePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate database connection
	if s.userThemeStore == nil {
		log.Printf("❌ User theme store not initialized")
		respondError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		log.Printf("❌ Invalid token for theme permissions request: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can view/manage theme permissions
	if claims.Role != "root" {
		log.Printf("🚫 User %s (role: %s) denied access to theme permissions", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem gerenciar permissões de tema")
		return
	}

	// Get permissions
	usersCanEdit, adminsCanEdit, err := s.userThemeStore.GetThemePermissions()
	if err != nil {
		log.Printf("❌ Error getting theme permissions: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao obter permissões de tema")
		return
	}

	respondJSON(w, http.StatusOK, ThemePermissionsResponse{
		UsersCanEditTheme:  usersCanEdit,
		AdminsCanEditTheme: adminsCanEdit,
	})
}

// HandleUpdateThemePermissions handles PUT /api/settings/theme-permissions
// Updates theme permission settings (root only)
func (s *Server) HandleUpdateThemePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate database connection
	if s.userThemeStore == nil {
		log.Printf("❌ User theme store not initialized")
		respondError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		log.Printf("❌ Invalid token for theme permissions update: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can manage theme permissions
	if claims.Role != "root" {
		log.Printf("🚫 User %s (role: %s) denied access to update theme permissions", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem gerenciar permissões de tema")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB is more than enough

	// Parse request
	var req ThemePermissionsRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		log.Printf("❌ Invalid request body from root user %s: %v", claims.Username, err)
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get old permissions for audit
	oldUsersCanEdit, oldAdminsCanEdit, _ := s.userThemeStore.GetThemePermissions()

	// Update permissions
	if err := s.userThemeStore.SetThemePermissions(req.UsersCanEditTheme, req.AdminsCanEditTheme); err != nil {
		log.Printf("❌ Error updating theme permissions: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao atualizar permissões de tema")
		return
	}

	log.Printf("✅ Root user %s updated theme permissions (users: %v -> %v, admins: %v -> %v)",
		claims.Username, oldUsersCanEdit, req.UsersCanEditTheme, oldAdminsCanEdit, req.AdminsCanEditTheme)
	log.Printf("✅ Root user %s updated theme permissions", claims.Username)

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Permissões de tema atualizadas com sucesso",
		Data: ThemePermissionsResponse{
			UsersCanEditTheme:  req.UsersCanEditTheme,
			AdminsCanEditTheme: req.AdminsCanEditTheme,
		},
	})
}

// HandleUserThemeRoute routes user theme requests
func (s *Server) HandleUserThemeRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetUserTheme(w, r)
	case http.MethodPut:
		s.HandleUpdateUserTheme(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// HandleThemePermissionsRoute routes theme permissions requests
func (s *Server) HandleThemePermissionsRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetThemePermissions(w, r)
	case http.MethodPut:
		s.HandleUpdateThemePermissions(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// ============================================
// Global Theme Handlers (Root Only)
// ============================================

// GlobalThemeRequest represents the request for setting global theme
type GlobalThemeRequest struct {
	ThemePreset        string  `json:"theme_preset"`
	PrimaryColor       *string `json:"primary_color,omitempty"`
	SecondaryColor     *string `json:"secondary_color,omitempty"`
	BackgroundColor    *string `json:"background_color,omitempty"`
	SurfaceColor       *string `json:"surface_color,omitempty"`
	TextColor          *string `json:"text_color,omitempty"`
	TextSecondaryColor *string `json:"text_secondary_color,omitempty"`
	BorderColor        *string `json:"border_color,omitempty"`
}

// HandleGetGlobalTheme handles GET /api/settings/global-theme
func (s *Server) HandleGetGlobalTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can view global theme settings
	if claims.Role != "root" {
		respondError(w, http.StatusForbidden, "Apenas usuários root podem acessar configurações de tema global")
		return
	}

	// Get global theme settings from system_settings
	settings, err := s.settingsStore.GetSystemSettings()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao carregar configurações")
		return
	}

	// Extract global theme values
	response := make(map[string]interface{})
	for key, value := range settings {
		if strings.HasPrefix(key, "global_theme.") {
			shortKey := strings.TrimPrefix(key, "global_theme.")
			response[shortKey] = value
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// HandleUpdateGlobalTheme handles PUT /api/settings/global-theme
func (s *Server) HandleUpdateGlobalTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can update global theme
	if claims.Role != "root" {
		log.Printf("🚫 User %s (role: %s) denied access to update global theme", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem alterar o tema global")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxThemeRequestSize)

	// Parse request
	var req GlobalThemeRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate preset - check for dangerous patterns
	lowerPreset := strings.ToLower(req.ThemePreset)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPreset, strings.ToLower(pattern)) {
			log.Printf("🚨 SECURITY: Potential injection detected in global theme preset: %s", req.ThemePreset)
			respondError(w, http.StatusBadRequest, "invalid characters in theme_preset")
			return
		}
	}
	if len(req.ThemePreset) > maxPresetLength {
		respondError(w, http.StatusBadRequest, "theme_preset too long")
		return
	}

	// Validate colors
	colorFields := map[string]*string{
		"primary_color":        req.PrimaryColor,
		"secondary_color":      req.SecondaryColor,
		"background_color":     req.BackgroundColor,
		"surface_color":        req.SurfaceColor,
		"text_color":           req.TextColor,
		"text_secondary_color": req.TextSecondaryColor,
		"border_color":         req.BorderColor,
	}

	for fieldName, color := range colorFields {
		if err := validateColorField(fieldName, color); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Save global theme settings
	s.settingsStore.UpdateSystemSetting("global_theme.preset", req.ThemePreset)
	if req.PrimaryColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.primary_color", *req.PrimaryColor)
	}
	if req.SecondaryColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.secondary_color", *req.SecondaryColor)
	}
	if req.BackgroundColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.background_color", *req.BackgroundColor)
	}
	if req.SurfaceColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.surface_color", *req.SurfaceColor)
	}
	if req.TextColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.text_color", *req.TextColor)
	}
	if req.TextSecondaryColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.text_secondary_color", *req.TextSecondaryColor)
	}
	if req.BorderColor != nil {
		s.settingsStore.UpdateSystemSetting("global_theme.border_color", *req.BorderColor)
	}

	log.Printf("✅ Root user %s updated global theme (preset: %s)", claims.Username, req.ThemePreset)

	// Log to audit
	if s.auditStore != nil {
		newValue := map[string]interface{}{
			"theme_preset": req.ThemePreset,
		}
		if req.PrimaryColor != nil {
			newValue["primary_color"] = *req.PrimaryColor
		}
		if req.SecondaryColor != nil {
			newValue["secondary_color"] = *req.SecondaryColor
		}
		if req.BackgroundColor != nil {
			newValue["background_color"] = *req.BackgroundColor
		}
		if req.SurfaceColor != nil {
			newValue["surface_color"] = *req.SurfaceColor
		}
		if req.TextColor != nil {
			newValue["text_color"] = *req.TextColor
		}
		if req.TextSecondaryColor != nil {
			newValue["text_secondary_color"] = *req.TextSecondaryColor
		}
		if req.BorderColor != nil {
			newValue["border_color"] = *req.BorderColor
		}

		_, auditErr := s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "global_theme",
			EntityID:      "system",
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue:      newValue,
			Status:        "success",
			ErrorMessage:  nil,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		if auditErr != nil {
			log.Printf("⚠️ Failed to log global theme update to audit: %v", auditErr)
		}
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Tema global atualizado com sucesso",
	})
}

// HandleGlobalThemeRoute routes global theme requests
func (s *Server) HandleGlobalThemeRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetGlobalTheme(w, r)
	case http.MethodPut:
		s.HandleUpdateGlobalTheme(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// ============================================
// Allowed Themes Handlers (Root Only)
// ============================================

// AllowedThemesRequest represents the request for setting allowed themes
type AllowedThemesRequest struct {
	AllowedThemes []string `json:"allowed_themes"`
}

// HandleGetAllowedThemes handles GET /api/settings/allowed-themes
func (s *Server) HandleGetAllowedThemes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	_, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Get allowed themes from system_settings
	settings, err := s.settingsStore.GetSystemSettings()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao carregar configurações")
		return
	}

	// Find allowed themes setting
	var allowedThemes []string
	if value, exists := settings["allowed_themes"]; exists && value != "" {
		allowedThemes = strings.Split(value, ",")
	}

	// Default: all themes allowed
	if len(allowedThemes) == 0 {
		allowedThemes = []string{"default", "ocean", "forest", "sunset", "purple", "monochrome", "custom"}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"allowed_themes": allowedThemes,
	})
}

// HandleUpdateAllowedThemes handles PUT /api/settings/allowed-themes
func (s *Server) HandleUpdateAllowedThemes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can update allowed themes
	if claims.Role != "root" {
		log.Printf("🚫 User %s (role: %s) denied access to update allowed themes", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem alterar os temas permitidos")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	// Parse request
	var req AllowedThemesRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate that at least one theme is allowed
	if len(req.AllowedThemes) == 0 {
		respondError(w, http.StatusBadRequest, "Pelo menos um tema deve estar permitido")
		return
	}

	// Validate theme names - check for dangerous patterns but allow any reasonable theme name
	for _, theme := range req.AllowedThemes {
		if err := validateThemeName(theme); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Save allowed themes
	themesStr := strings.Join(req.AllowedThemes, ",")
	if err := s.settingsStore.UpdateSystemSetting("allowed_themes", themesStr); err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao salvar configurações")
		return
	}

	log.Printf("✅ Root user %s updated allowed themes: %v", claims.Username, req.AllowedThemes)

	// Log to audit
	if s.auditStore != nil {
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "allowed_themes",
			EntityID:      "system",
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue: map[string]interface{}{
				"allowed_themes": req.AllowedThemes,
			},
			Status:        "success",
			ErrorMessage:  nil,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Temas permitidos atualizados com sucesso",
	})
}

// HandleAllowedThemesRoute routes allowed themes requests
func (s *Server) HandleAllowedThemesRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetAllowedThemes(w, r)
	case http.MethodPut:
		s.HandleUpdateAllowedThemes(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// ============================================
// System Config Handlers (Root Only)
// ============================================

// SystemConfigRequest represents the request for system configuration
type SystemConfigRequest struct {
	LoginBlockTime    int    `json:"login_block_time"`
	LoginAttempts     int    `json:"login_attempts"`
	NotificationEmail string `json:"notification_email"`
	NotificationPhone string `json:"notification_phone"`
}

// HandleGetSystemConfig handles GET /api/settings/system-config
func (s *Server) HandleGetSystemConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can view system config
	if claims.Role != "root" {
		respondError(w, http.StatusForbidden, "Apenas usuários root podem acessar configurações do sistema")
		return
	}

	// Get system settings
	settings, err := s.settingsStore.GetSystemSettings()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao carregar configurações")
		return
	}

	// Extract system config values with defaults
	response := map[string]interface{}{
		"login_block_time":   300,
		"login_attempts":     5,
		"notification_email": "",
		"notification_phone": "",
	}

	for key, value := range settings {
		switch key {
		case "system.login_block_time":
			if val, err := strconv.Atoi(value); err == nil {
				response["login_block_time"] = val
			}
		case "system.login_attempts":
			if val, err := strconv.Atoi(value); err == nil {
				response["login_attempts"] = val
			}
		case "system.notification_email":
			response["notification_email"] = value
		case "system.notification_phone":
			response["notification_phone"] = value
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// HandleUpdateSystemConfig handles PUT /api/settings/system-config
func (s *Server) HandleUpdateSystemConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Only root can update system config
	if claims.Role != "root" {
		log.Printf("🚫 User %s (role: %s) denied access to update system config", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem alterar configurações do sistema")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	// Parse request
	var req SystemConfigRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate login_block_time (60-3600 seconds)
	if req.LoginBlockTime < 60 || req.LoginBlockTime > 3600 {
		respondError(w, http.StatusBadRequest, "Tempo de bloqueio deve estar entre 60 e 3600 segundos")
		return
	}

	// Validate login_attempts (3-10)
	if req.LoginAttempts < 3 || req.LoginAttempts > 10 {
		respondError(w, http.StatusBadRequest, "Tentativas de login devem estar entre 3 e 10")
		return
	}

	// Save system config
	s.settingsStore.UpdateSystemSetting("system.login_block_time", strconv.Itoa(req.LoginBlockTime))
	s.settingsStore.UpdateSystemSetting("system.login_attempts", strconv.Itoa(req.LoginAttempts))

	// Email and phone are for future implementation - store but don't use yet
	if req.NotificationEmail != "" {
		s.settingsStore.UpdateSystemSetting("system.notification_email", req.NotificationEmail)
	}
	if req.NotificationPhone != "" {
		s.settingsStore.UpdateSystemSetting("system.notification_phone", req.NotificationPhone)
	}

	log.Printf("✅ Root user %s updated system config (block_time: %d, attempts: %d)",
		claims.Username, req.LoginBlockTime, req.LoginAttempts)

	// Log to audit
	if s.auditStore != nil {
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "system_config",
			EntityID:      "system",
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue: map[string]interface{}{
				"login_block_time": req.LoginBlockTime,
				"login_attempts":   req.LoginAttempts,
			},
			Status:        "success",
			ErrorMessage:  nil,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Configurações do sistema atualizadas com sucesso",
	})
}

// HandleSystemConfigRoute routes system config requests
func (s *Server) HandleSystemConfigRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetSystemConfig(w, r)
	case http.MethodPut:
		s.HandleUpdateSystemConfig(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// validateThemeName validates that a theme name is safe and reasonable
func validateThemeName(theme string) error {
	if theme == "" {
		return fmt.Errorf("nome do tema não pode estar vazio")
	}

	if len(theme) > 50 {
		return fmt.Errorf("nome do tema muito longo (máximo 50 caracteres)")
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(theme), strings.ToLower(pattern)) {
			return fmt.Errorf("nome do tema contém caracteres inválidos")
		}
	}

	// Allow alphanumeric, hyphens, and underscores
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(theme) {
		return fmt.Errorf("nome do tema deve conter apenas letras, números, hífens e underscores")
	}

	return nil
}

// getGlobalThemeSettings retrieves the global theme settings from system_settings
func (s *Server) getGlobalThemeSettings() *store.UserThemeSettings {
	if s.settingsStore == nil {
		return nil
	}

	settings, err := s.settingsStore.GetSystemSettings()
	if err != nil {
		log.Printf("⚠️ Error getting global theme settings: %v", err)
		return nil
	}

	globalTheme := &store.UserThemeSettings{
		ThemePreset:    "default",
		ThemeMode:      "system",
		HighContrast:   false,
		ColorBlindMode: "none",
	}

	// Parse global theme settings
	for key, value := range settings {
		switch key {
		case "global_theme.preset":
			globalTheme.ThemePreset = value
		case "global_theme.primary_color":
			if value != "" {
				globalTheme.PrimaryColor = &value
			}
		case "global_theme.secondary_color":
			if value != "" {
				globalTheme.SecondaryColor = &value
			}
		case "global_theme.background_color":
			if value != "" {
				globalTheme.BackgroundColor = &value
			}
		case "global_theme.surface_color":
			if value != "" {
				globalTheme.SurfaceColor = &value
			}
		case "global_theme.text_color":
			if value != "" {
				globalTheme.TextColor = &value
			}
		case "global_theme.text_secondary_color":
			if value != "" {
				globalTheme.TextSecondaryColor = &value
			}
		case "global_theme.border_color":
			if value != "" {
				globalTheme.BorderColor = &value
			}
		}
	}

	return globalTheme
}
