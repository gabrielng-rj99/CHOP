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
	"errors"
	"testing"
)

// TestNewValidationError tests the creation of ValidationError
func TestNewValidationError(t *testing.T) {
	tests := []struct {
		name    string
		message string
		err     error
		want    string
	}{
		{
			name:    "validation error with message only",
			message: "invalid email format",
			err:     nil,
			want:    "invalid email format",
		},
		{
			name:    "validation error with wrapped error",
			message: "validation failed",
			err:     errors.New("database error"),
			want:    "validation failed: database error",
		},
		{
			name:    "validation error with empty message",
			message: "",
			err:     nil,
			want:    "",
		},
		{
			name:    "validation error with empty message and error",
			message: "",
			err:     errors.New("some error"),
			want:    ": some error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := NewValidationError(tt.message, tt.err)
			if ve.Error() != tt.want {
				t.Errorf("expected '%s', got '%s'", tt.want, ve.Error())
			}
		})
	}
}

// TestValidationErrorError tests the Error method implementation
func TestValidationErrorError(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		innerErr error
		want     string
	}{
		{
			name:     "error with message only",
			message:  "client name cannot be empty",
			innerErr: nil,
			want:     "client name cannot be empty",
		},
		{
			name:     "error with wrapped database error",
			message:  "failed to create client",
			innerErr: errors.New("database connection lost"),
			want:     "failed to create client: database connection lost",
		},
		{
			name:     "error with long message",
			message:  "registration ID must be a valid CPF or CNPJ, format is XXX.XXX.XXX-XX or XX.XXX.XXX/XXXX-XX",
			innerErr: nil,
			want:     "registration ID must be a valid CPF or CNPJ, format is XXX.XXX.XXX-XX or XX.XXX.XXX/XXXX-XX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := NewValidationError(tt.message, tt.innerErr)
			if ve.Error() != tt.want {
				t.Errorf("expected '%s', got '%s'", tt.want, ve.Error())
			}
		})
	}
}

// TestValidationErrorUnwrap tests the Unwrap method
func TestValidationErrorUnwrap(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		innerErr   error
		shouldFail bool
	}{
		{
			name:       "unwrap with no inner error",
			message:    "validation failed",
			innerErr:   nil,
			shouldFail: false,
		},
		{
			name:       "unwrap with inner error",
			message:    "validation failed",
			innerErr:   errors.New("database error"),
			shouldFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := NewValidationError(tt.message, tt.innerErr)
			unwrapped := ve.Unwrap()

			if tt.innerErr == nil {
				if unwrapped != nil {
					t.Errorf("expected nil, got %v", unwrapped)
				}
			} else {
				if unwrapped == nil {
					t.Error("expected error, got nil")
				}
				if unwrapped.Error() != tt.innerErr.Error() {
					t.Errorf("expected '%s', got '%s'", tt.innerErr.Error(), unwrapped.Error())
				}
			}
		})
	}
}

// TestIsValidationError tests the IsValidationError helper function
func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		isValidation bool
	}{
		{
			name:         "validation error returns true",
			err:          NewValidationError("test error", nil),
			isValidation: true,
		},
		{
			name:         "validation error with wrapped error returns true",
			err:          NewValidationError("test error", errors.New("inner")),
			isValidation: true,
		},
		{
			name:         "regular error returns false",
			err:          errors.New("regular error"),
			isValidation: false,
		},
		{
			name:         "nil error returns false",
			err:          nil,
			isValidation: false,
		},
		{
			name:         "other error types return false",
			err:          errors.New("some other error"),
			isValidation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			if result != tt.isValidation {
				t.Errorf("expected %v, got %v", tt.isValidation, result)
			}
		})
	}
}

// TestValidationErrorChain tests error chaining with Is and As
func TestValidationErrorChain(t *testing.T) {
	innerErr := errors.New("inner validation error")
	ve := NewValidationError("validation failed", innerErr)

	// Test that Unwrap returns the inner error
	unwrapped := ve.Unwrap()
	if unwrapped != innerErr {
		t.Error("unwrapped error should be the inner error")
	}

	// Test that the error chain is correct
	var ve2 *ValidationError
	if !errors.As(ve, &ve2) {
		t.Error("should be able to cast to ValidationError")
	}

	if ve2.Error() != ve.Error() {
		t.Error("error messages should match after casting")
	}
}

// TestValidationErrorImplementsError tests that ValidationError implements error interface
func TestValidationErrorImplementsError(t *testing.T) {
	ve := NewValidationError("test", nil)
	var _ error = ve

	// Test that Error() method exists and returns a string
	errorMsg := ve.Error()
	if errorMsg == "" && ve != nil {
		// OK, message can be empty
	}
	if len(errorMsg) > 0 && errorMsg != "test" {
		t.Errorf("expected 'test', got '%s'", errorMsg)
	}
}
