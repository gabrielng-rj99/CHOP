// Contracts-Manager/backend/domain/models.go

package domain

import (
	"time"
)

// Client representa a tabela 'clients'
type Client struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	RegistrationID    *string    `json:"registration_id,omitempty"`    // CPF/CNPJ (opcional)
	Nickname          *string    `json:"nickname,omitempty"`           // Apelido/Nome fantasia (opcional)
	BirthDate         *time.Time `json:"birth_date,omitempty"`         // Data de nascimento/fundação (opcional)
	Email             *string    `json:"email,omitempty"`              // Email do cliente (opcional)
	Phone             *string    `json:"phone,omitempty"`              // Telefone do cliente (opcional)
	Address           *string    `json:"address,omitempty"`            // Endereço (opcional)
	Notes             *string    `json:"notes,omitempty"`              // Observações gerais (opcional)
	Status            string     `json:"status"`                       // Status: ativo, inativo, etc.
	Tags              *string    `json:"tags,omitempty"`               // Tags separadas por vírgula (opcional)
	ContactPreference *string    `json:"contact_preference,omitempty"` // Preferência de contato (whatsapp, email, etc.)
	LastContactDate   *time.Time `json:"last_contact_date,omitempty"`  // Data do último contato (opcional)
	NextActionDate    *time.Time `json:"next_action_date,omitempty"`   // Próxima ação planejada (opcional)
	CreatedAt         time.Time  `json:"created_at"`                   // Data de cadastro
	Documents         *string    `json:"documents,omitempty"`          // Lista de documentos/links (opcional)
	ArchivedAt        *time.Time `json:"archived_at"`                  // Soft delete via archived_at
}

// Dependent representa a tabela 'dependents' (Client Dependent, como unidades, filhos, parentes)
type Dependent struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	ClientID          string     `json:"client_id"`
	Description       *string    `json:"description,omitempty"`        // Descrição livre (opcional)
	BirthDate         *time.Time `json:"birth_date,omitempty"`         // Data de nascimento/fundação (opcional)
	Email             *string    `json:"email,omitempty"`              // Email do dependente (opcional)
	Phone             *string    `json:"phone,omitempty"`              // Telefone do dependente (opcional)
	Address           *string    `json:"address,omitempty"`            // Endereço (opcional)
	Notes             *string    `json:"notes,omitempty"`              // Observações (opcional)
	Status            string     `json:"status"`                       // Status: ativo, inativo, etc.
	Tags              *string    `json:"tags,omitempty"`               // Tags separadas por vírgula (opcional)
	ContactPreference *string    `json:"contact_preference,omitempty"` // Preferência de contato (opcional)
	Documents         *string    `json:"documents,omitempty"`          // Lista de documentos/links (opcional)
}

// Category representa a tabela 'categories'
type Category struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	ArchivedAt *time.Time `json:"archived_at"`
}

// Line representa a tabela 'lines' (Product Line)
type Line struct {
	ID         string     `json:"id"`
	Line       string     `json:"line" db:"name"`
	CategoryID string     `json:"category_id"`
	ArchivedAt *time.Time `json:"archived_at"`
}

// Contract representa a tabela 'contracts'
type Contract struct {
	ID          string     `json:"id"`
	Model       string     `json:"model" db:"name"`
	ProductKey  string     `json:"product_key"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	EndDate     *time.Time `json:"end_date,omitempty"`
	LineID      string     `json:"line_id"`
	ClientID    string     `json:"client_id"`
	DependentID *string    `json:"dependent_id"` // Usamos um ponteiro para que possa ser nulo
	ArchivedAt  *time.Time `json:"archived_at"`
}

// User representa um usuário do sistema para autenticação
type User struct {
	ID             string     `json:"id"`
	Username       *string    `json:"username"`
	DisplayName    *string    `json:"display_name"`
	PasswordHash   string     `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
	Role           *string    `json:"role"` // "user", "admin", "root"
	FailedAttempts int        `json:"failed_attempts"`
	LockLevel      int        `json:"lock_level"`
	LockedUntil    *time.Time `json:"locked_until"`
	AuthSecret     string     `json:"auth_secret"`
}

// GetEffectiveStartDate retorna a data de início efetiva para cálculos.
// Se StartDate for nil, retorna time.Time{} (infinito inferior) para indicar que começou "sempre".
func (c *Contract) GetEffectiveStartDate() time.Time {
	if c.StartDate == nil {
		return time.Time{}
	}
	return *c.StartDate
}

// GetEffectiveEndDate retorna a data de fim efetiva para cálculos.
// Se EndDate for nil, retorna uma data muito distante no futuro (infinito superior) para indicar que nunca expira.
func (c *Contract) GetEffectiveEndDate() time.Time {
	if c.EndDate == nil {
		return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	return *c.EndDate
}

// IsActive verifica se o contrato está ativo no momento especificado.
// StartDate nil = começou sempre (infinito inferior)
// EndDate nil = nunca expira (infinito superior)
func (c *Contract) IsActive(at time.Time) bool {
	effectiveStart := c.GetEffectiveStartDate()
	effectiveEnd := c.GetEffectiveEndDate()

	// Se StartDate é nil (infinito inferior), sempre começou
	startedAlready := effectiveStart.IsZero() || !at.Before(effectiveStart)

	// Se EndDate é nil (infinito superior), nunca expira
	notExpired := at.Before(effectiveEnd)

	return startedAlready && notExpired
}

// Status calcula e retorna o estado atual do contrato (Ativo, Expirando, Expirado).
func (c *Contract) Status() string {
	now := time.Now()

	// EndDate nil = nunca expira, sempre "Ativo"
	if c.EndDate == nil {
		return "Ativo"
	}

	effectiveEnd := c.GetEffectiveEndDate()

	if effectiveEnd.Before(now) {
		return "Expirado"
	}

	// Consideramos "Expirando em Breve" se faltar 30 dias ou menos.
	daysUntilExpiration := effectiveEnd.Sub(now).Hours() / 24
	if daysUntilExpiration <= 30 {
		return "Expirando em Breve"
	}

	return "Ativo"
}

// AuditLog representa a tabela 'audit_logs' para rastreamento de auditoria
type AuditLog struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Operation       string    `json:"operation"` // 'create', 'update', 'delete', 'read'
	Entity          string    `json:"entity"`    // 'client', 'contract', 'user', 'line', 'category', 'dependent'
	EntityID        string    `json:"entity_id"`
	AdminID         *string   `json:"admin_id,omitempty"`
	AdminUsername   *string   `json:"admin_username,omitempty"`
	OldValue        *string   `json:"old_value,omitempty"` // JSON string com valores antigos
	NewValue        *string   `json:"new_value,omitempty"` // JSON string com valores novos
	Status          string    `json:"status"`              // 'success', 'error'
	ErrorMessage    *string   `json:"error_message,omitempty"`
	IPAddress       *string   `json:"ip_address,omitempty"`
	UserAgent       *string   `json:"user_agent,omitempty"`
	RequestMethod   *string   `json:"request_method,omitempty"`    // GET, POST, PUT, DELETE
	RequestPath     *string   `json:"request_path,omitempty"`      // /api/users, /api/clients, etc
	RequestID       *string   `json:"request_id,omitempty"`        // Correlação entre requisições
	ResponseCode    *int      `json:"response_code,omitempty"`     // HTTP status code
	ExecutionTimeMs *int      `json:"execution_time_ms,omitempty"` // Tempo de execução em ms
}
