package settingsstore

import (
	"testing"
)

func TestSettingsStore(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test db: %v", err)
	}
	// No cleanup returned, assuming db is closed by global teardown or we defer CloseDB() if available.
	// But SetupTestDB uses a global testDB. safe.

	// Clear table before test
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	s := NewSettingsStore(db)

	t.Run("GetSystemSettings returns empty map initially", func(t *testing.T) {
		settings, err := s.GetSystemSettings()
		if err != nil {
			t.Fatalf("Failed to get settings: %v", err)
		}
		if len(settings) != 0 {
			t.Errorf("Expected 0 settings, got %d", len(settings))
		}
	})

	t.Run("UpdateSystemSetting inserts new setting", func(t *testing.T) {
		err := s.UpdateSystemSetting("branding.appName", "Test App")
		if err != nil {
			t.Fatalf("Failed to update setting: %v", err)
		}

		val, err := s.GetSystemSetting("branding.appName")
		if err != nil {
			t.Fatalf("Failed to get setting: %v", err)
		}
		if val != "Test App" {
			t.Errorf("Expected 'Test App', got '%s'", val)
		}
	})

	t.Run("UpdateSystemSetting updates existing setting", func(t *testing.T) {
		err := s.UpdateSystemSetting("branding.appName", "Updated App")
		if err != nil {
			t.Fatalf("Failed to update setting: %v", err)
		}

		val, err := s.GetSystemSetting("branding.appName")
		if err != nil {
			t.Fatalf("Failed to get setting: %v", err)
		}
		if val != "Updated App" {
			t.Errorf("Expected 'Updated App', got '%s'", val)
		}
	})

	t.Run("GetSystemSettings returns all settings", func(t *testing.T) {
		s.UpdateSystemSetting("theme.primary", "#000000")

		settings, err := s.GetSystemSettings()
		if err != nil {
			t.Fatalf("Failed to get settings: %v", err)
		}

		if len(settings) != 2 { // branding.appName + theme.primary
			t.Errorf("Expected 2 settings, got %d", len(settings))
		}
		if settings["branding.appName"] != "Updated App" {
			t.Errorf("Expected branding.appName to be 'Updated App'")
		}
		if settings["theme.primary"] != "#000000" {
			t.Errorf("Expected theme.primary to be '#000000'")
		}
	})
}
