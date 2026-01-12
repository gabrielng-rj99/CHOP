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

package domain

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

var (
	// Regex para validação de ID (UUID v4)
	uuidRegex = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	// Regex para telefone simples (apenas números, min 10 dígitos)
	phoneRegex = regexp.MustCompile(`^\d{10,}$`)
)

// ValidateUUID verifica se o ID é um UUID válido
func ValidateUUID(id string) error {
	if !uuidRegex.MatchString(id) {
		return errors.New("id inválido: deve ser um UUID v4")
	}
	return nil
}

// ValidateEmail verifica se o email é válido
func ValidateEmail(email string) error {
	if len(email) > 254 {
		return errors.New("email inválido: muito longo")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("email inválido")
	}
	return nil
}

// ValidatePhone verifica se o telefone contém apenas números e tem comprimento mínimo
func ValidatePhone(phone string) error {
	if !phoneRegex.MatchString(phone) {
		return errors.New("telefone inválido: deve conter apenas números (mínimo 10 dígitos)")
	}
	return nil
}

// NormalizeEmail normaliza o email (trim + lowercase)
func NormalizeEmail(email *string) *string {
	if email == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*email)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	return &lower
}

// NormalizePhone normaliza o telefone (trim)
// TODO: Integrar com lib de telefone se necessário
func NormalizePhone(phone *string) *string {
	if phone == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*phone)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// ValidateClient valida os campos obrigatórios de um Cliente
func ValidateClient(c *Client) error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("nome é obrigatório")
	}
	if len(c.Name) < 3 {
		return errors.New("nome deve ter pelo menos 3 caracteres")
	}

	if c.Email != nil && *c.Email != "" {
		if err := ValidateEmail(*c.Email); err != nil {
			return err
		}
	}

	if c.Phone != nil && *c.Phone != "" {
		if err := ValidatePhone(*c.Phone); err != nil {
			return err
		}
	}

	// Validação de RegistrationID (CNPJ/CPF) poderia ser adicionada aqui
	// Por enquanto apenas verifica se não é vazio se estiver presente
	if c.RegistrationID != nil && strings.TrimSpace(*c.RegistrationID) == "" {
		return errors.New("registration_id não pode ser vazio se fornecido")
	}

	if c.BirthDate != nil {
		if c.BirthDate.After(time.Now()) {
			return errors.New("data de nascimento não pode ser no futuro")
		}
		if c.BirthDate.Before(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)) {
			return errors.New("data de nascimento não pode ser anterior a 1900")
		}
	}

	if c.NextActionDate != nil {
		now := time.Now()
		if c.NextActionDate.After(now.AddDate(10, 0, 0)) {
			return errors.New("next_action_date não pode ser mais de 10 anos no futuro")
		}
		if c.NextActionDate.Before(now.AddDate(-1, 0, 0)) {
			return errors.New("next_action_date não pode ser mais de 1 ano no passado")
		}
	}

	if c.Notes != nil && len(*c.Notes) > 50000 {
		return errors.New("notes não pode ter mais de 50.000 caracteres")
	}

	if c.Documents != nil && len(*c.Documents) > 10000 {
		return errors.New("documents não pode ter mais de 10.000 caracteres")
	}

	return nil
}

// ValidateCategory valida uma categoria
func ValidateCategory(c *Category) error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("nome da categoria é obrigatório")
	}
	return nil
}

// ValidateSubcategory valida uma subcategoria
func ValidateSubcategory(s *Subcategory) error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("nome da subcategoria é obrigatório")
	}
	if err := ValidateUUID(s.CategoryID); err != nil {
		return fmt.Errorf("category_id inválido: %v", err)
	}
	return nil
}

// ValidateContract valida um contrato
func ValidateContract(c *Contract) error {
	// Model is optional - removed mandatory check

	if err := ValidateUUID(c.ClientID); err != nil {
		return fmt.Errorf("client_id inválido: %v", err)
	}

	if err := ValidateUUID(c.SubcategoryID); err != nil {
		return fmt.Errorf("subcategory_id inválido: %v", err)
	}

	if c.AffiliateID != nil && *c.AffiliateID != "" {
		if err := ValidateUUID(*c.AffiliateID); err != nil {
			return fmt.Errorf("affiliate_id inválido: %v", err)
		}
	}

	if c.StartDate != nil && c.EndDate != nil {
		if c.EndDate.Before(*c.StartDate) {
			return errors.New("data de término não pode ser anterior à data de início")
		}
	}

	return nil
}

// ValidateUser valida dados de usuário
func ValidateUser(u *User) error {
	if u.Username != nil {
		if len(*u.Username) < 3 {
			return errors.New("username deve ter pelo menos 3 caracteres")
		}
		// Regex para username seguro (letras, numeros, underline, traço)
		match, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, *u.Username)
		if !match {
			return errors.New("username contém caracteres inválidos")
		}
	}

	if u.DisplayName != nil && len(*u.DisplayName) < 2 {
		return errors.New("display_name deve ter pelo menos 2 caracteres")
	}

	return nil
}

// ValidateAffiliate valida um afiliado
func ValidateAffiliate(a *Affiliate) error {
	if strings.TrimSpace(a.Name) == "" {
		return errors.New("nome é obrigatório")
	}

	if err := ValidateUUID(a.ClientID); err != nil {
		return fmt.Errorf("client_id inválido: %v", err)
	}

	if a.Email != nil && *a.Email != "" {
		if err := ValidateEmail(*a.Email); err != nil {
			return err
		}
	}

	return nil
}
