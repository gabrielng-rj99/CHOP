package domain

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/nyaruka/phonenumbers"
)

// ValidationError representa um erro de validação
type ValidationError struct {
	Field   string
	Message string
}

func (v ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// ValidationErrors é uma coleção de erros de validação
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}
	var msgs []string
	for _, v := range ve {
		msgs = append(msgs, v.Error())
	}
	return strings.Join(msgs, "; ")
}

// IsValid verifica se há erros de validação
func (ve ValidationErrors) IsValid() bool {
	return len(ve) == 0
}

// Padrão regex para validação de email
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateClientEmail valida o formato do email e verifica MX do domínio
func ValidateClientEmail(email *string) error {
	if email == nil || *email == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*email)
	if trimmed == "" {
		return nil
	}

	if len(trimmed) > 254 {
		return ValidationError{
			Field:   "email",
			Message: "email não pode ter mais de 254 caracteres",
		}
	}

	if !emailRegex.MatchString(trimmed) {
		return ValidationError{
			Field:   "email",
			Message: "email possui um formato inválido",
		}
	}

	parts := strings.Split(trimmed, "@")
	if len(parts) != 2 {
		return ValidationError{
			Field:   "email",
			Message: "email deve conter exatamente um símbolo '@'",
		}
	}

	localPart := parts[0]
	domain := parts[1]

	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return ValidationError{
			Field:   "email",
			Message: "parte local do email não pode começar ou terminar com ponto",
		}
	}

	if strings.Contains(localPart, "..") {
		return ValidationError{
			Field:   "email",
			Message: "email não pode conter pontos consecutivos",
		}
	}

	if !strings.Contains(domain, ".") {
		return ValidationError{
			Field:   "email",
			Message: "domínio do email deve conter pelo menos um ponto",
		}
	}

	// Verificação MX do domínio - valida se o domínio está apto a receber emails
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return ValidationError{
			Field:   "email",
			Message: "domínio do email não está apto a receber emails (MX ausente)",
		}
	}

	return nil
}

// ValidateClientPhone valida o telefone usando padrão internacional E.164
func ValidateClientPhone(phone *string) error {
	if phone == nil || *phone == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*phone)
	if trimmed == "" {
		return nil
	}

	// Tentar extrair o código de país do número
	var phoneNumber *phonenumbers.PhoneNumber
	var err error

	// Se o número começa com +, tenta parsear como E.164
	if strings.HasPrefix(trimmed, "+") {
		phoneNumber, err = phonenumbers.Parse(trimmed, "")
	} else {
		// Se não tem +, assume que é do Brasil (BR) por padrão
		// Você pode mudar isso se quiser outro país padrão
		phoneNumber, err = phonenumbers.Parse(trimmed, "BR")
	}

	if err != nil {
		return ValidationError{
			Field:   "phone",
			Message: "formato de telefone inválido. Use formato E.164 com código de país (ex: +55 11 98765-4321)",
		}
	}

	// Validar se o número é válido para o país
	if !phonenumbers.IsValidNumber(phoneNumber) {
		return ValidationError{
			Field:   "phone",
			Message: "número de telefone inválido para o país especificado",
		}
	}

	return nil
}

// ValidateClient valida todos os campos obrigatórios e opcionais de um cliente
func ValidateClient(client *Client) ValidationErrors {
	var errors ValidationErrors

	if client == nil {
		errors = append(errors, ValidationError{
			Field:   "client",
			Message: "cliente não pode ser nulo",
		})
		return errors
	}

	// Validações de campos obrigatórios
	if strings.TrimSpace(client.Name) == "" {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "nome do cliente é obrigatório",
		})
	}

	if len(client.Name) > 255 {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "nome do cliente não pode ter mais de 255 caracteres",
		})
	}

	// Status é obrigatório
	if strings.TrimSpace(client.Status) == "" {
		errors = append(errors, ValidationError{
			Field:   "status",
			Message: "status do cliente é obrigatório",
		})
	}

	// Validações de campos opcionais
	if client.RegistrationID != nil && len(*client.RegistrationID) > 20 {
		errors = append(errors, ValidationError{
			Field:   "registration_id",
			Message: "ID de registro não pode ter mais de 20 caracteres",
		})
	}

	if client.Nickname != nil && len(*client.Nickname) > 255 {
		errors = append(errors, ValidationError{
			Field:   "nickname",
			Message: "apelido não pode ter mais de 255 caracteres",
		})
	}

	if client.Address != nil && len(*client.Address) > 1000 {
		errors = append(errors, ValidationError{
			Field:   "address",
			Message: "endereço não pode ter mais de 1000 caracteres",
		})
	}

	// Validação de Notes - limite de 50.000 caracteres
	if client.Notes != nil && len(*client.Notes) > 50000 {
		errors = append(errors, ValidationError{
			Field:   "notes",
			Message: "notas não podem ter mais de 50.000 caracteres",
		})
	}

	// Validação de Documents - limite de 10.000 caracteres
	if client.Documents != nil && len(*client.Documents) > 10000 {
		errors = append(errors, ValidationError{
			Field:   "documents",
			Message: "documentos não podem ter mais de 10.000 caracteres",
		})
	}

	// Validação de BirthDate
	if client.BirthDate != nil {
		now := time.Now()

		// Data não pode estar no futuro
		if client.BirthDate.After(now) {
			errors = append(errors, ValidationError{
				Field:   "birth_date",
				Message: "data de nascimento não pode estar no futuro",
			})
		}

		// Data não pode ser anterior a 1900
		minDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		if client.BirthDate.Before(minDate) {
			errors = append(errors, ValidationError{
				Field:   "birth_date",
				Message: "data de nascimento não pode ser anterior a 1900",
			})
		}
	}

	// Validação de NextActionDate
	if client.NextActionDate != nil {
		now := time.Now()

		// Data não pode estar muito no passado (mais de 1 ano)
		oneYearAgo := now.AddDate(-1, 0, 0)
		if client.NextActionDate.Before(oneYearAgo) {
			errors = append(errors, ValidationError{
				Field:   "next_action_date",
				Message: "próxima ação não pode estar mais de 1 ano no passado",
			})
		}

		// Data não pode estar muito no futuro (mais de 10 anos)
		tenYearsFromNow := now.AddDate(10, 0, 0)
		if client.NextActionDate.After(tenYearsFromNow) {
			errors = append(errors, ValidationError{
				Field:   "next_action_date",
				Message: "próxima ação não pode estar mais de 10 anos no futuro",
			})
		}
	}

	if client.ContactPreference != nil {
		validPreferences := map[string]bool{
			"whatsapp": true,
			"email":    true,
			"phone":    true,
			"sms":      true,
			"outros":   true,
		}
		pref := strings.ToLower(strings.TrimSpace(*client.ContactPreference))
		if pref != "" && !validPreferences[pref] {
			errors = append(errors, ValidationError{
				Field:   "contact_preference",
				Message: "preferência de contato inválida (use: whatsapp, email, phone, sms, outros)",
			})
		}
	}

	if emailErr := ValidateClientEmail(client.Email); emailErr != nil {
		if valErr, ok := emailErr.(ValidationError); ok {
			errors = append(errors, valErr)
		}
	}

	if phoneErr := ValidateClientPhone(client.Phone); phoneErr != nil {
		if valErr, ok := phoneErr.(ValidationError); ok {
			errors = append(errors, valErr)
		}
	}

	return errors
}

// NormalizeEmail remove espaços e converte para minúsculas
func NormalizeEmail(email *string) *string {
	if email == nil || *email == "" {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(*email))
	if normalized == "" {
		return nil
	}
	return &normalized
}

// NormalizePhone formata o telefone para E.164
func NormalizePhone(phone *string) *string {
	if phone == nil || *phone == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*phone)
	if trimmed == "" {
		return nil
	}

	var phoneNumber *phonenumbers.PhoneNumber
	var err error

	if strings.HasPrefix(trimmed, "+") {
		phoneNumber, err = phonenumbers.Parse(trimmed, "")
	} else {
		phoneNumber, err = phonenumbers.Parse(trimmed, "BR")
	}

	if err != nil {
		// Se não conseguir parsear, retorna o original
		return &trimmed
	}

	// Formatar em padrão E.164
	formatted := phonenumbers.Format(phoneNumber, phonenumbers.E164)
	return &formatted
}

// ValidateDependent valida todos os campos obrigatórios e opcionais de um dependente
func ValidateDependent(dependent *Dependent) ValidationErrors {
	var errors ValidationErrors

	if dependent == nil {
		errors = append(errors, ValidationError{
			Field:   "dependent",
			Message: "dependente não pode ser nulo",
		})
		return errors
	}

	// Validações de campos obrigatórios
	if strings.TrimSpace(dependent.Name) == "" {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "nome do dependente é obrigatório",
		})
	}

	if len(dependent.Name) > 255 {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "nome do dependente não pode ter mais de 255 caracteres",
		})
	}

	if strings.TrimSpace(dependent.ClientID) == "" {
		errors = append(errors, ValidationError{
			Field:   "client_id",
			Message: "ID do cliente é obrigatório",
		})
	}

	// Status é obrigatório
	if strings.TrimSpace(dependent.Status) == "" {
		errors = append(errors, ValidationError{
			Field:   "status",
			Message: "status do dependente é obrigatório",
		})
	}

	// Validações de campos opcionais
	if dependent.Description != nil && len(*dependent.Description) > 1000 {
		errors = append(errors, ValidationError{
			Field:   "description",
			Message: "descrição não pode ter mais de 1000 caracteres",
		})
	}

	if dependent.Address != nil && len(*dependent.Address) > 1000 {
		errors = append(errors, ValidationError{
			Field:   "address",
			Message: "endereço não pode ter mais de 1000 caracteres",
		})
	}

	// Validação de Notes - limite de 50.000 caracteres
	if dependent.Notes != nil && len(*dependent.Notes) > 50000 {
		errors = append(errors, ValidationError{
			Field:   "notes",
			Message: "notas não podem ter mais de 50.000 caracteres",
		})
	}

	// Validação de Documents - limite de 10.000 caracteres
	if dependent.Documents != nil && len(*dependent.Documents) > 10000 {
		errors = append(errors, ValidationError{
			Field:   "documents",
			Message: "documentos não podem ter mais de 10.000 caracteres",
		})
	}

	// Validação de BirthDate
	if dependent.BirthDate != nil {
		now := time.Now()

		// Data não pode estar no futuro
		if dependent.BirthDate.After(now) {
			errors = append(errors, ValidationError{
				Field:   "birth_date",
				Message: "data de nascimento não pode estar no futuro",
			})
		}

		// Data não pode ser anterior a 1900
		minDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		if dependent.BirthDate.Before(minDate) {
			errors = append(errors, ValidationError{
				Field:   "birth_date",
				Message: "data de nascimento não pode ser anterior a 1900",
			})
		}
	}

	if dependent.ContactPreference != nil {
		validPreferences := map[string]bool{
			"whatsapp": true,
			"email":    true,
			"phone":    true,
			"sms":      true,
			"outros":   true,
		}
		pref := strings.ToLower(strings.TrimSpace(*dependent.ContactPreference))
		if pref != "" && !validPreferences[pref] {
			errors = append(errors, ValidationError{
				Field:   "contact_preference",
				Message: "preferência de contato inválida (use: whatsapp, email, phone, sms, outros)",
			})
		}
	}

	if emailErr := ValidateClientEmail(dependent.Email); emailErr != nil {
		if valErr, ok := emailErr.(ValidationError); ok {
			errors = append(errors, valErr)
		}
	}

	if phoneErr := ValidateClientPhone(dependent.Phone); phoneErr != nil {
		if valErr, ok := phoneErr.(ValidationError); ok {
			errors = append(errors, valErr)
		}
	}

	return errors
}
