package domain

import (
	"fmt"
	"regexp"
	"strings"

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

// ValidateClientEmail valida o formato do email
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

	if strings.TrimSpace(client.RegistrationID) == "" {
		errors = append(errors, ValidationError{
			Field:   "registration_id",
			Message: "ID de registro do cliente é obrigatório",
		})
	}

	if len(client.RegistrationID) > 20 {
		errors = append(errors, ValidationError{
			Field:   "registration_id",
			Message: "ID de registro não pode ter mais de 20 caracteres",
		})
	}

	// Validações de campos opcionais
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
