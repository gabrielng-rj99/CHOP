package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"testing"
	"time"
)

// TestGetAllLicenses tests the GetAllLicenses method
func TestGetAllLicenses(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	licenseStore := store.NewLicenseStore(db)

	// Setup dependencies
	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	tests := []struct {
		name          string
		licensesToAdd int
		expectedCount int
	}{
		{
			name:          "empty database",
			licensesToAdd: 0,
			expectedCount: 0,
		},
		{
			name:          "single license",
			licensesToAdd: 1,
			expectedCount: 1,
		},
		{
			name:          "multiple licenses",
			licensesToAdd: 5,
			expectedCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear licenses for each test
			if _, err := db.Exec("DELETE FROM licenses"); err != nil {
				t.Fatalf("Failed to clear licenses: %v", err)
			}

			// Add licenses
			for i := 0; i < tt.licensesToAdd; i++ {
				license := domain.License{
					Model:      "Test License",
					ProductKey: "KEY-" + string(rune(48+i)),
					StartDate:  time.Now().AddDate(0, 0, i*30),
					EndDate:    time.Now().AddDate(0, 0, (i+1)*30),
					LineID:     lineID,
					ClientID:   clientID,
					EntityID:   &entityID,
				}
				_, err := licenseStore.CreateLicense(license)
				if err != nil {
					t.Fatalf("Failed to create license: %v", err)
				}
			}

			// Test GetAllLicenses
			licenses, err := licenseStore.GetAllLicenses()
			if err != nil {
				t.Errorf("GetAllLicenses failed: %v", err)
			}

			if len(licenses) != tt.expectedCount {
				t.Errorf("Expected %d licenses, got %d", tt.expectedCount, len(licenses))
			}

			// Verify all licenses have required fields
			for _, license := range licenses {
				if license.ID == "" {
					t.Error("License ID is empty")
				}
				if license.Model == "" {
					t.Error("License Model is empty")
				}
				if license.ProductKey == "" {
					t.Error("License ProductKey is empty")
				}
			}
		})
	}
}

// TestGetLicensesByLineID tests filtering licenses by line ID
func TestGetLicensesByLineID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	licenseStore := store.NewLicenseStore(db)

	// Setup dependencies
	clientID, entityID, categoryID, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second line in the same category
	lineID2, err := InsertTestLine(db, "Test Line 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to create second line: %v", err)
	}

	// Create licenses for both lines
	license1 := domain.License{
		Model:      "License Line 1",
		ProductKey: "KEY-LINE1-001",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	_, err = licenseStore.CreateLicense(license1)
	if err != nil {
		t.Fatalf("Failed to create license 1: %v", err)
	}

	license2 := domain.License{
		Model:      "License Line 2",
		ProductKey: "KEY-LINE2-001",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID2,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	_, err = licenseStore.CreateLicense(license2)
	if err != nil {
		t.Fatalf("Failed to create license 2: %v", err)
	}

	tests := []struct {
		name          string
		queryLineID   string
		expectedCount int
		shouldError   bool
	}{
		{
			name:          "valid line with licenses",
			queryLineID:   lineID,
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name:          "valid line with different licenses",
			queryLineID:   lineID2,
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name:          "empty line ID",
			queryLineID:   "",
			expectedCount: 0,
			shouldError:   true,
		},
		{
			name:          "non-existent line ID",
			queryLineID:   "non-existent-id",
			expectedCount: 0,
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses, err := licenseStore.GetLicensesByLineID(tt.queryLineID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(licenses) != tt.expectedCount {
				t.Errorf("Expected %d licenses, got %d", tt.expectedCount, len(licenses))
			}

			// Verify licenses belong to the queried line
			for _, license := range licenses {
				if license.LineID != tt.queryLineID {
					t.Errorf("License LineID %s doesn't match query LineID %s", license.LineID, tt.queryLineID)
				}
			}
		})
	}
}

// TestGetLicensesByCategoryID tests filtering licenses by category ID
func TestGetLicensesByCategoryID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	licenseStore := store.NewLicenseStore(db)

	// Setup dependencies
	clientID, entityID, categoryID, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second category with its own line
	categoryID2, err := InsertTestCategory(db, "Test Category 2")
	if err != nil {
		t.Fatalf("Failed to create second category: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Test Line in Category 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to create line in second category: %v", err)
	}

	// Create licenses in both categories
	license1 := domain.License{
		Model:      "License Category 1",
		ProductKey: "KEY-CAT1-001",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	_, err = licenseStore.CreateLicense(license1)
	if err != nil {
		t.Fatalf("Failed to create license in category 1: %v", err)
	}

	license2 := domain.License{
		Model:      "License Category 2",
		ProductKey: "KEY-CAT2-001",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID2,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	_, err = licenseStore.CreateLicense(license2)
	if err != nil {
		t.Fatalf("Failed to create license in category 2: %v", err)
	}

	tests := []struct {
		name            string
		queryCategoryID string
		expectedCount   int
		shouldError     bool
	}{
		{
			name:            "valid category with licenses",
			queryCategoryID: categoryID,
			expectedCount:   1,
			shouldError:     false,
		},
		{
			name:            "valid category with different licenses",
			queryCategoryID: categoryID2,
			expectedCount:   1,
			shouldError:     false,
		},
		{
			name:            "empty category ID",
			queryCategoryID: "",
			expectedCount:   0,
			shouldError:     true,
		},
		{
			name:            "non-existent category ID",
			queryCategoryID: "non-existent-id",
			expectedCount:   0,
			shouldError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses, err := licenseStore.GetLicensesByCategoryID(tt.queryCategoryID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(licenses) != tt.expectedCount {
				t.Errorf("Expected %d licenses, got %d", tt.expectedCount, len(licenses))
			}

			// Verify licenses belong to lines in the queried category
			for _, license := range licenses {
				var lineCategory string
				err := db.QueryRow("SELECT category_id FROM lines WHERE id = ?", license.LineID).Scan(&lineCategory)
				if err != nil {
					t.Errorf("Failed to verify license's line category: %v", err)
				}
				if lineCategory != tt.queryCategoryID {
					t.Errorf("License's line category %s doesn't match query category %s", lineCategory, tt.queryCategoryID)
				}
			}
		})
	}
}

// TestGetAllLicensesWithMultipleClients tests GetAllLicenses with licenses from different clients
func TestGetAllLicensesWithMultipleClients(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	licenseStore := store.NewLicenseStore(db)

	// Create two clients with their dependencies
	client1ID, entity1ID, _, line1ID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Test Client 2", "12.345.678/0001-99")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestEntity(db, "Entity 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create entity 2: %v", err)
	}
	category2ID, err := InsertTestCategory(db, "Category 2")
	if err != nil {
		t.Fatalf("Failed to create category 2: %v", err)
	}
	line2ID, err := InsertTestLine(db, "Line 2", category2ID)
	if err != nil {
		t.Fatalf("Failed to create line 2: %v", err)
	}

	// Create licenses for both clients
	for i := 0; i < 3; i++ {
		license := domain.License{
			Model:      "License Client 1",
			ProductKey: "KEY-C1-" + string(rune(48+i)),
			StartDate:  time.Now().AddDate(0, 0, i*30),
			EndDate:    time.Now().AddDate(0, 0, (i+1)*30),
			LineID:     line1ID,
			ClientID:   client1ID,
			EntityID:   &entity1ID,
		}
		_, err := licenseStore.CreateLicense(license)
		if err != nil {
			t.Fatalf("Failed to create license for client 1: %v", err)
		}
	}

	for i := 0; i < 2; i++ {
		license := domain.License{
			Model:      "License Client 2",
			ProductKey: "KEY-C2-" + string(rune(48+i)),
			StartDate:  time.Now().AddDate(0, 1, i*30),
			EndDate:    time.Now().AddDate(0, 1, (i+1)*30),
			LineID:     line2ID,
			ClientID:   client2ID,
			EntityID:   &entity2ID,
		}
		_, err := licenseStore.CreateLicense(license)
		if err != nil {
			t.Fatalf("Failed to create license for client 2: %v", err)
		}
	}

	// Test GetAllLicenses returns all licenses
	licenses, err := licenseStore.GetAllLicenses()
	if err != nil {
		t.Errorf("GetAllLicenses failed: %v", err)
	}

	expectedTotal := 5
	if len(licenses) != expectedTotal {
		t.Errorf("Expected %d total licenses, got %d", expectedTotal, len(licenses))
	}

	// Verify we have licenses from both clients
	client1Count := 0
	client2Count := 0
	for _, license := range licenses {
		if license.ClientID == client1ID {
			client1Count++
		} else if license.ClientID == client2ID {
			client2Count++
		}
	}

	if client1Count != 3 {
		t.Errorf("Expected 3 licenses for client 1, got %d", client1Count)
	}
	if client2Count != 2 {
		t.Errorf("Expected 2 licenses for client 2, got %d", client2Count)
	}
}

// TestGetLicensesByLineIDWithMultipleClients tests that GetLicensesByLineID returns licenses from all clients
func TestGetLicensesByLineIDWithMultipleClients(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	licenseStore := store.NewLicenseStore(db)

	// Create two clients
	client1ID, entity1ID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Test Client 2", "98.765.432/0001-11")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestEntity(db, "Entity 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create entity 2: %v", err)
	}

	// Create licenses for the same line but different clients
	license1 := domain.License{
		Model:      "License Client 1",
		ProductKey: "KEY-SAME-001",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   client1ID,
		EntityID:   &entity1ID,
	}
	_, err = licenseStore.CreateLicense(license1)
	if err != nil {
		t.Fatalf("Failed to create license for client 1: %v", err)
	}

	license2 := domain.License{
		Model:      "License Client 2",
		ProductKey: "KEY-SAME-002",
		StartDate:  time.Now(),
		EndDate:    time.Now().AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   client2ID,
		EntityID:   &entity2ID,
	}
	_, err = licenseStore.CreateLicense(license2)
	if err != nil {
		t.Fatalf("Failed to create license for client 2: %v", err)
	}

	// Test GetLicensesByLineID returns licenses from both clients
	licenses, err := licenseStore.GetLicensesByLineID(lineID)
	if err != nil {
		t.Errorf("GetLicensesByLineID failed: %v", err)
	}

	if len(licenses) != 2 {
		t.Errorf("Expected 2 licenses for line, got %d", len(licenses))
	}

	// Verify we have licenses from both clients
	client1Found := false
	client2Found := false
	for _, license := range licenses {
		if license.ClientID == client1ID {
			client1Found = true
		}
		if license.ClientID == client2ID {
			client2Found = true
		}
	}

	if !client1Found {
		t.Error("License from client 1 not found")
	}
	if !client2Found {
		t.Error("License from client 2 not found")
	}
}
