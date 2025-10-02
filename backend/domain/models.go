// backend/domain/models.go

package domain

import (
	"time"
)

// Company representa a tabela 'companies'
type Company struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CNPJ       string     `json:"cnpj"`
	ArchivedAt *time.Time `json:"archived_at,omitempty"` // NOVO: Usamos ponteiro para permitir valor nulo
}

// Unit representa a tabela 'units'
type Unit struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CompanyID string `json:"company_id"`
}

// Category representa a tabela 'categories'
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Type representa a tabela 'types'
type Type struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CategoryID string `json:"category_id"`
}

// License representa a tabela 'licenses'
type License struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ProductKey string    `json:"product_key"`
	StartDate  time.Time `json:"start_date"`
	EndDate    time.Time `json:"end_date"`
	TypeID     string    `json:"type_id"`
	CompanyID  string    `json:"company_id"`
	UnitID     *string   `json:"unit_id"` // Usamos um ponteiro para que possa ser nulo
}

// Status calcula e retorna o estado atual da licença (Ativa, Expirando, Expirada).
func (l *License) Status() string {
	now := time.Now()

	if l.EndDate.Before(now) {
		return "Expirada"
	}

	// Consideramos "Expirando em Breve" se faltar 30 dias ou menos.
	daysUntilExpiration := l.EndDate.Sub(now).Hours() / 24
	if daysUntilExpiration <= 30 {
		return "Expirando em Breve"
	}

	return "Ativa"
}

