package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func setupLicenseTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

// TestGetLicensesExpiringSoon tests retrieving licenses expiring within a specified number of days
func TestGetLicensesExpiringSoon(t *testing.T) {
	db := setupLicenseTestDB(t)
	defer CloseDB(db)

	licenseStore := store.NewLicenseStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Insert licenses with different expiration dates
	// License 1: expires in 10 days (should be included in 30-day search)
	_, err = InsertTestLicense(db, "License 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 10), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 1: %v", err)
	}

	// License 2: expires in 60 days (should NOT be included in 30-day search)
	_, err = InsertTestLicense(db, "License 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 60), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 2: %v", err)
	}

	// License 3: already expired (should NOT be included)
	_, err = InsertTestLicense(db, "License 3", "KEY-3", now.AddDate(0, 0, -30), now.AddDate(0, 0, -5), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 3: %v", err)
	}

	// License 4: expires in 25 days (should be included in 30-day search)
	_, err = InsertTestLicense(db, "License 4", "KEY-4", now.AddDate(0, 0, -10), now.AddDate(0, 0, 25), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 4: %v", err)
	}

	// Get licenses expiring in 30 days
	licenses, err := licenseStore.GetLicensesExpiringSoon(30)
	if err != nil {
		t.Fatalf("Failed to get expiring licenses: %v", err)
	}

	if len(licenses) != 2 {
		t.Errorf("Expected 2 expiring licenses, got %d", len(licenses))
	}

	// Verify correct licenses are returned
	expiredKeys := make(map[string]bool)
	for _, l := range licenses {
		expiredKeys[l.ProductKey] = true
	}

	if !expiredKeys["KEY-1"] || !expiredKeys["KEY-4"] {
		t.Error("Expected licenses KEY-1 and KEY-4 in results")
	}
}

// TestGetLicensesByLineIDCritical tests retrieving licenses by line ID
func TestGetLicensesByLineIDCritical(t *testing.T) {
	db := setupLicenseTestDB(t)
	defer CloseDB(db)

	licenseStore := store.NewLicenseStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID1, err := InsertTestLine(db, "Line 1", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Line 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert licenses for different lines
	_, err = InsertTestLicense(db, "License 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 1: %v", err)
	}

	_, err = InsertTestLicense(db, "License 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 2: %v", err)
	}

	_, err = InsertTestLicense(db, "License 3", "KEY-3", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID2, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 3: %v", err)
	}

	// Get licenses for lineID1
	licenses, err := licenseStore.GetLicensesByLineID(lineID1)
	if err != nil {
		t.Fatalf("Failed to get licenses by line: %v", err)
	}

	if len(licenses) != 2 {
		t.Errorf("Expected 2 licenses for line 1, got %d", len(licenses))
	}

	// Verify all returned licenses belong to lineID1
	for _, l := range licenses {
		if l.LineID != lineID1 {
			t.Errorf("Expected line ID '%s', got '%s'", lineID1, l.LineID)
		}
	}
}

// TestGetLicensesByCategoryIDCritical tests retrieving licenses by category ID
func TestGetLicensesByCategoryIDCritical(t *testing.T) {
	db := setupLicenseTestDB(t)
	defer CloseDB(db)

	licenseStore := store.NewLicenseStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert test category 2: %v", err)
	}

	lineID1, err := InsertTestLine(db, "Line 1", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Line 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert licenses for different categories
	_, err = InsertTestLicense(db, "License 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 1: %v", err)
	}

	_, err = InsertTestLicense(db, "License 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 2: %v", err)
	}

	_, err = InsertTestLicense(db, "License 3", "KEY-3", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID2, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert license 3: %v", err)
	}

	// Get licenses for categoryID1
	licenses, err := licenseStore.GetLicensesByCategoryID(categoryID1)
	if err != nil {
		t.Fatalf("Failed to get licenses by category: %v", err)
	}

	if len(licenses) != 2 {
		t.Errorf("Expected 2 licenses for category 1, got %d", len(licenses))
	}

	// Verify all returned licenses belong to categoryID1
	for _, l := range licenses {
		if l.LineID != lineID1 {
			t.Errorf("Expected line ID '%s', got '%s'", lineID1, l.LineID)
		}
	}
}

// TestCreateLicenseWithOverlap tests license creation fails when there's a time overlap
func TestCreateLicenseWithOverlap(t *testing.T) {
	db := setupLicenseTestDB(t)
	defer CloseDB(db)

	licenseStore := store.NewLicenseStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first license
	firstLicense := domain.License{
		Model:      "First License",
		ProductKey: "KEY-1",
		StartDate:  now.AddDate(0, 0, -10),
		EndDate:    now.AddDate(0, 0, 30),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id, err := licenseStore.CreateLicense(firstLicense)
	if err != nil {
		t.Fatalf("Failed to create first license: %v", err)
	}
	if id == "" {
		t.Error("Expected license ID")
	}

	// Try to create overlapping license
	overlappingLicense := domain.License{
		Model:      "Overlapping License",
		ProductKey: "KEY-2",
		StartDate:  now.AddDate(0, 0, 5),  // Within first license period
		EndDate:    now.AddDate(0, 0, 20), // Within first license period
		LineID:     lineID,
		ClientID:   clientID,
	}

	_, err = licenseStore.CreateLicense(overlappingLicense)
	if err == nil {
		t.Error("Expected error creating overlapping license")
	}
}

// TestCreateLicenseNonOverlappingValid tests that non-overlapping licenses can be created
func TestCreateLicenseNonOverlappingValid(t *testing.T) {
	db := setupLicenseTestDB(t)
	defer CloseDB(db)

	licenseStore := store.NewLicenseStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first license
	firstLicense := domain.License{
		Model:      "First License",
		ProductKey: "KEY-1",
		StartDate:  now.AddDate(0, 0, -30),
		EndDate:    now.AddDate(0, 0, -5),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id, err := licenseStore.CreateLicense(firstLicense)
	if err != nil {
		t.Fatalf("Failed to create first license: %v", err)
	}
	if id == "" {
		t.Error("Expected license ID")
	}

	// Create non-overlapping license (starts after first ends)
	secondLicense := domain.License{
		Model:      "Second License",
		ProductKey: "KEY-2",
		StartDate:  now.AddDate(0, 0, -4),
		EndDate:    now.AddDate(0, 0, 30),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id2, err := licenseStore.CreateLicense(secondLicense)
	if err != nil {
		t.Fatalf("Failed to create second license: %v", err)
	}
	if id2 == "" {
		t.Error("Expected license ID for second license")
	}
}
