// Licenses-Manager/backend/domain/models.go

package domain

import (
	"time"
)

// Client representa a tabela 'clients'
type Client struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	RegistrationID string     `json:"registration_id"`
	ArchivedAt     *time.Time `json:"archived_at,omitempty"` // NOVO: Usamos ponteiro para permitir valor nulo
}

// Entity representa a tabela 'entities' (entidades)
type Entity struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
}

// Category representa a tabela 'categories'
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Line representa a tabela 'lines'
type Line struct {
	ID         string `json:"id"`
	Line       string `json:"line" db:"name"`
	CategoryID string `json:"category_id"`
}

// License representa a tabela 'licenses'
type License struct {
	ID         string     `json:"id"`
	Model      string     `json:"model" db:"name"`
	ProductKey string     `json:"product_key"`
	StartDate  time.Time  `json:"start_date"`
	EndDate    time.Time  `json:"end_date"`
	LineID     string     `json:"line_id"`
	ClientID   string     `json:"client_id"`
	EntityID   *string    `json:"entity_id"` // Usamos um ponteiro para que possa ser nulo
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// User representa um usuário do sistema para autenticação
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	Role         string    `json:"role"` // "user", "admin", "full_admin"
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
