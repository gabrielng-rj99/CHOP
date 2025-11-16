package store

import (
	"time"

	"github.com/google/uuid"
)

// generateUniqueCNPJ generates a unique CNPJ for testing purposes
func generateUniqueCNPJ() string {
	uniqueID := uuid.New().String()[:8]
	return uniqueID[0:2] + "." + uniqueID[2:5] + ".111/0001-11"
}

// timePtr is a helper function to convert time.Time to *time.Time for tests
func timePtr(t time.Time) *time.Time {
	return &t
}
