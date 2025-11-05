// Contracts-Manager/backend/domain/models.go

package domain

import (
	"time"
)

// Client representa a tabela 'clients'
type Client struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	RegistrationID string     `json:"registration_id"`
	Email          *string    `json:"email,omitempty"`       // Email do cliente (opcional)
	Phone          *string    `json:"phone,omitempty"`       // Telefone do cliente (opcional)
	ArchivedAt     *time.Time `json:"archived_at,omitempty"` // Soft delete via archived_at
}

// Dependent representa a tabela 'dependents' (Client Dependent, como unidades, filhos, parentes)
type Dependent struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
}

// Category representa a tabela 'categories'
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Line representa a tabela 'lines' (Product Line)
type Line struct {
	ID         string `json:"id"`
	Line       string `json:"line" db:"name"`
	CategoryID string `json:"category_id"`
}

// Contract representa a tabela 'contracts'
type Contract struct {
	ID          string     `json:"id"`
	Model       string     `json:"model" db:"name"`
	ProductKey  string     `json:"product_key"`
	StartDate   time.Time  `json:"start_date"`
	EndDate     time.Time  `json:"end_date"`
	LineID      string     `json:"line_id"`
	ClientID    string     `json:"client_id"`
	DependentID *string    `json:"dependent_id"` // Usamos um ponteiro para que possa ser nulo
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
}

// User representa um usuário do sistema para autenticação
type User struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	DisplayName    string     `json:"display_name"`
	PasswordHash   string     `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	Role           string     `json:"role"` // "user", "admin", "full_admin"
	FailedAttempts int        `json:"failed_attempts"`
	LockLevel      int        `json:"lock_level"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
}

// Status calcula e retorna o estado atual do contrato (Ativo, Expirando, Expirado).
func (c *Contract) Status() string {
	now := time.Now()

	if c.EndDate.Before(now) {
		return "Expirado"
	}

	// Consideramos "Expirando em Breve" se faltar 30 dias ou menos.
	daysUntilExpiration := c.EndDate.Sub(now).Hours() / 24
	if daysUntilExpiration <= 30 {
		return "Expirando em Breve"
	}

	return "Ativo"
}

// AuditLog representa a tabela 'audit_logs' para rastreamento de auditoria
type AuditLog struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Operation     string    `json:"operation"` // 'create', 'update', 'delete', 'read'
	Entity        string    `json:"entity"`    // 'client', 'contract', 'user', 'line', 'category', 'dependent'
	EntityID      string    `json:"entity_id"`
	AdminID       string    `json:"admin_id"`
	AdminUsername string    `json:"admin_username,omitempty"`
	OldValue      *string   `json:"old_value,omitempty"` // JSON string com valores antigos
	NewValue      *string   `json:"new_value,omitempty"` // JSON string com valores novos
	Status        string    `json:"status"`              // 'success', 'error'
	ErrorMessage  *string   `json:"error_message,omitempty"`
	IPAddress     *string   `json:"ip_address,omitempty"`
	UserAgent     *string   `json:"user_agent,omitempty"`
}
