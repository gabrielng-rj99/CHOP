// Package store provides the error types and handling for the license management system.
// This file contains custom error types used throughout the store package to provide
// more specific error information and handling capabilities.
package store

import "errors"

// Erros específicos do domínio
var (
	ErrCompanyNotFound          = errors.New("empresa não encontrada")
	ErrCompanyHasActiveLicenses = errors.New("empresa possui licenças ativas")
	ErrDuplicatedCNPJ           = errors.New("CNPJ já cadastrado")
	ErrUnitNotFound             = errors.New("unidade não encontrada")
	ErrUnitHasActiveLicenses    = errors.New("unidade possui licenças ativas")
	ErrInvalidCompanyUnit       = errors.New("unidade não pertence à empresa")
	ErrTypeNotFound             = errors.New("tipo de licença não encontrado")
	ErrLicenseNotFound          = errors.New("licença não encontrada")
	ErrLicenseOverlap           = errors.New("já existe uma licença do mesmo tipo neste período")
	ErrArchivedCompany          = errors.New("empresa está arquivada")
	ErrNoRows                   = errors.New("nenhum registro encontrado")
)

// ValidationError represents an error that occurs when input validation fails.
// It is used to distinguish validation errors from other types of errors (like database errors)
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
