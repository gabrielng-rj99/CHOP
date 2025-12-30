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

// Package store provides the error subcategories and handling for the license management system.
// This file contains custom error subcategories used throughout the store package to provide
// more specific error information and handling capabilities.
package store

import "errors"

// Domain-specific errors
var (
	ErrClientNotFound           = errors.New("client not found")
	ErrClientHasActiveLicenses  = errors.New("client has active licenses")
	ErrDuplicatedRegistrationID = errors.New("registration ID already registered")

	ErrInvalidClientClient = errors.New("client does not belong to the client")
	ErrLineNotFound        = errors.New("license type not found")
	ErrLicenseNotFound     = errors.New("license not found")
	ErrLicenseOverlap      = errors.New("there is already a license of the same type in this period")
	ErrArchivedClient      = errors.New("client is archived")
	ErrNoRows              = errors.New("no records found")
)

// ValidationError represents an error that occurs when input validation fails.
// It is used to distinguish validation errors from other subcategories of errors (like database errors)
// and provides a consistent way to handle validation failures across the application.
type ValidationError struct {
	message string
	err     error
}

// NewValidationError creates a new validation error with the given message.
// This is the preferred way to create ValidationError instances as it ensures
// proper initialization and consistency in error creation.
//
// Parameters:
//   - message: A descriptive message explaining why the validation failed
//
// Returns:
//   - *ValidationError: A pointer to the newly created validation error
func NewValidationError(message string, err error) *ValidationError {
	return &ValidationError{
		message: message,
		err:     err,
	}
}

// Error implements the error interface for ValidationError.
// This method is required to satisfy the error interface and allows
// ValidationError to be used anywhere a standard error is expected.
//
// Returns:
//   - string: The error message associated with this validation error
func (e *ValidationError) Error() string {
	if e.err != nil {
		return e.message + ": " + e.err.Error()
	}
	return e.message
}

func (e *ValidationError) Unwrap() error {
	return e.err
}

// IsValidationError checks if an error is a ValidationError.
// This helper function can be used to determine if an error is specifically
// a validation error, which allows for different error handling paths in the application.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - bool: true if the error is a ValidationError, false otherwise
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}
