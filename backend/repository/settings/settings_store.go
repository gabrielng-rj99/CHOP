package settingsstore

import (
	"database/sql"
	"fmt"

	"Open-Generic-Hub/backend/repository"
)

// SystemSetting represents a key-value configuration setting
type SystemSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SettingsStore manages system configuration settings
type SettingsStore struct {
	db repository.DBInterface
}

// NewSettingsStore creates a new instance of SettingsStore
func NewSettingsStore(db repository.DBInterface) *SettingsStore {
	return &SettingsStore{
		db: db,
	}
}

// GetSystemSettings retrieves all system settings
func (s *SettingsStore) GetSystemSettings() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM system_settings")
	if err != nil {
		return nil, fmt.Errorf("failed to query settings: %v", err)
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan setting: %v", err)
		}
		settings[key] = value
	}
	return settings, nil
}

// GetSystemSetting retrieves a single setting by key
func (s *SettingsStore) GetSystemSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM system_settings WHERE key = $1", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil // Return empty if not found
	}
	if err != nil {
		return "", fmt.Errorf("failed to get setting %s: %v", key, err)
	}
	return value, nil
}

// UpdateSystemSetting updates or inserts a system setting
func (s *SettingsStore) UpdateSystemSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO system_settings (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, key, value)
	if err != nil {
		return fmt.Errorf("failed to update setting %s: %v", key, err)
	}
	return nil
}
