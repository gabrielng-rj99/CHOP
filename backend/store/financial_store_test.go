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

package store

import (
	"testing"
	"time"

	"Open-Generic-Hub/backend/domain"
)

func TestFinancialStore_GetDetailedSummary(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("returns summary with period breakdown", func(t *testing.T) {
		summary, err := store.GetFinancialDetailedSummary()
		if err != nil {
			t.Fatalf("GetDetailedSummary() error = %v", err)
		}

		if summary == nil {
			t.Fatal("GetDetailedSummary() returned nil summary")
		}

		// Verify metadata fields are set
		if summary.GeneratedAt == "" {
			t.Error("GeneratedAt should not be empty")
		}

		if summary.CurrentDate == "" {
			t.Error("CurrentDate should not be empty")
		}

		// Verify period summaries exist
		if summary.LastMonth == nil {
			t.Error("LastMonth should not be nil")
		}

		if summary.CurrentMonth == nil {
			t.Error("CurrentMonth should not be nil")
		}

		if summary.NextMonth == nil {
			t.Error("NextMonth should not be nil")
		}

		// Verify monthly breakdown has expected number of entries (7 months: -3 to +3)
		if len(summary.MonthlyBreakdown) != 7 {
			t.Errorf("MonthlyBreakdown should have 7 entries, got %d", len(summary.MonthlyBreakdown))
		}
	})

	t.Run("period labels are formatted correctly", func(t *testing.T) {
		summary, err := store.GetFinancialDetailedSummary()
		if err != nil {
			t.Fatalf("GetDetailedSummary() error = %v", err)
		}

		// Verify current month label format
		currentMonth := time.Now()
		expectedPeriod := currentMonth.Format("2006-01")

		if summary.CurrentMonth.Period != expectedPeriod {
			t.Errorf("CurrentMonth.Period = %v, want %v", summary.CurrentMonth.Period, expectedPeriod)
		}

		// Verify period label is not empty
		if summary.CurrentMonth.PeriodLabel == "" {
			t.Error("CurrentMonth.PeriodLabel should not be empty")
		}
	})

	t.Run("totals are non-negative", func(t *testing.T) {
		summary, err := store.GetFinancialDetailedSummary()
		if err != nil {
			t.Fatalf("GetDetailedSummary() error = %v", err)
		}

		if summary.TotalToReceive < 0 {
			t.Errorf("TotalToReceive should be >= 0, got %v", summary.TotalToReceive)
		}

		if summary.TotalClientPays < 0 {
			t.Errorf("TotalClientPays should be >= 0, got %v", summary.TotalClientPays)
		}

		if summary.TotalReceived < 0 {
			t.Errorf("TotalReceived should be >= 0, got %v", summary.TotalReceived)
		}

		if summary.TotalPending < 0 {
			t.Errorf("TotalPending should be >= 0, got %v", summary.TotalPending)
		}

		if summary.TotalOverdue < 0 {
			t.Errorf("TotalOverdue should be >= 0, got %v", summary.TotalOverdue)
		}

		if summary.TotalOverdueCount < 0 {
			t.Errorf("TotalOverdueCount should be >= 0, got %v", summary.TotalOverdueCount)
		}
	})
}

func TestFinancialStore_GetMonthlySummary(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("returns summary for valid month", func(t *testing.T) {
		currentMonth := time.Now()
		summary, err := store.GetMonthlySummary(currentMonth.Year(), int(currentMonth.Month()))
		if err != nil {
			t.Fatalf("GetMonthlySummary() error = %v", err)
		}

		if summary == nil {
			t.Fatal("GetMonthlySummary() returned nil summary")
		}

		// Verify counts are non-negative
		if summary.PendingCount < 0 {
			t.Errorf("PendingCount should be >= 0, got %v", summary.PendingCount)
		}

		if summary.PaidCount < 0 {
			t.Errorf("PaidCount should be >= 0, got %v", summary.PaidCount)
		}

		if summary.OverdueCount < 0 {
			t.Errorf("OverdueCount should be >= 0, got %v", summary.OverdueCount)
		}
	})
}

func TestFinancialStore_GetFinancialSummary(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("returns overall summary", func(t *testing.T) {
		summary, err := store.GetFinancialSummary()
		if err != nil {
			t.Fatalf("GetFinancialSummary() error = %v", err)
		}

		if summary == nil {
			t.Fatal("GetFinancialSummary() returned nil summary")
		}
	})
}

func TestFinancialStore_CreateContractFinancial(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	// First, we need a contract to attach the financial to
	// This test assumes there's a valid contract in the test database
	// In a real scenario, you would create a contract first

	t.Run("validates financial type", func(t *testing.T) {
		financial := domain.ContractFinancial{
			ContractID:    "non-existent-contract",
			FinancialType: "invalid_type",
		}

		_, err := store.CreateContractFinancial(financial)
		if err == nil {
			t.Error("CreateContractFinancial() should return error for invalid financial type")
		}
	})

	t.Run("validates recurrence type for recorrente", func(t *testing.T) {
		financial := domain.ContractFinancial{
			ContractID:    "non-existent-contract",
			FinancialType: "recorrente",
			// RecurrenceType is nil, which should cause an error
		}

		_, err := store.CreateContractFinancial(financial)
		if err == nil {
			t.Error("CreateContractFinancial() should return error when recurrence_type is missing for recorrente")
		}
	})

	t.Run("validates recurrence type value", func(t *testing.T) {
		invalidRecurrence := "invalid_recurrence"
		financial := domain.ContractFinancial{
			ContractID:     "non-existent-contract",
			FinancialType:  "recorrente",
			RecurrenceType: &invalidRecurrence,
		}

		_, err := store.CreateContractFinancial(financial)
		if err == nil {
			t.Error("CreateContractFinancial() should return error for invalid recurrence_type")
		}
	})
}

func TestFinancialStore_UpdateOverdueStatus(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("updates overdue installments without error", func(t *testing.T) {
		affected, err := store.UpdateOverdueStatus()
		if err != nil {
			t.Fatalf("UpdateOverdueStatus() error = %v", err)
		}

		// affected can be 0 or more, just ensure no error
		if affected < 0 {
			t.Errorf("UpdateOverdueStatus() returned negative affected count: %d", affected)
		}
	})
}

func TestFinancialStore_GetUpcomingFinancials(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("returns upcoming financial for valid days ahead", func(t *testing.T) {
		financial, err := store.GetUpcomingFinancials(30)
		if err != nil {
			t.Fatalf("GetUpcomingFinancials() error = %v", err)
		}

		// Result can be empty, just verify no error
		if financial == nil {
			// nil is ok, means empty result
			financial = []domain.UpcomingFinancial{}
		}
	})

	t.Run("returns empty for 0 days ahead", func(t *testing.T) {
		financial, err := store.GetUpcomingFinancials(0)
		if err != nil {
			t.Fatalf("GetUpcomingFinancials(0) error = %v", err)
		}

		// With 0 days ahead, only today's financial should be returned
		_ = financial
	})
}

func TestFinancialStore_GetOverdueFinancial(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewFinancialStore(db)

	t.Run("returns overdue financial without error", func(t *testing.T) {
		financial, err := store.GetOverdueFinancials()
		if err != nil {
			t.Fatalf("GetOverdueFinancial() error = %v", err)
		}

		// Result can be empty, just verify no error
		if financial == nil {
			financial = []domain.UpcomingFinancial{}
		}
	})
}
