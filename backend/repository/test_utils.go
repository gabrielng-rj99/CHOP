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

package repository

import (
	"time"

	"github.com/google/uuid"
)

// Note: We use reflection/interfaces to avoid import cycles with subpackages
// The actual store constructors are available in each subpackage's test_helpers_test.go

// generateUniqueCNPJ generates a unique CNPJ for testing purposes
func generateUniqueCNPJ() string {
	uniqueID := uuid.New().String()[:8]
	return uniqueID[0:2] + "." + uniqueID[2:5] + ".111/0001-11"
}

// timePtr is a helper function to convert time.Time to *time.Time for tests
func timePtr(t time.Time) *time.Time {
	return &t
}
