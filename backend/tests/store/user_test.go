package tests

import (
	"testing"

	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
)

// Helper para criar UserStore com banco em memória
func setupUserStore(t *testing.T) *store.UserStore {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Erro ao abrir banco em memória: %v", err)
	}
	// Cria tabela users com todos os campos necessários
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		);
	`)
	if err != nil {
		t.Fatalf("Erro ao criar tabela users: %v", err)
	}
	return store.NewUserStore(db)
}

func TestEditUserAdminFlagPermissions(t *testing.T) {
	userStore := setupUserStore(t)

	// Cria usuário admin (sem número)
	_, err := userStore.CreateUser("admin", "Administrador", "SenhaForte123!@#abc", "full_admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário full_admin: %v", err)
	}

	// Cria usuário admin-0
	_, err = userStore.CreateUser("admin-0", "Admin Zero", "SenhaForte123!@#abc", "admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário admin-0: %v", err)
	}

	// Cria usuário normal
	_, err = userStore.CreateUser("user1", "Usuário Um", "SenhaForte123!@#abc", "user")
	if err != nil {
		t.Fatalf("Erro ao criar usuário normal: %v", err)
	}

	// Tenta alterar role de user1 usando admin-0 (não deve permitir)
	err = userStore.EditUserRole("admin-0", "user1", "admin")
	if err == nil {
		t.Error("admin-0 NÃO deveria poder alterar o role de outro usuário")
	}

	// Tenta alterar role de admin-0 usando admin-0 (não deve permitir)
	err = userStore.EditUserRole("admin-0", "admin-0", "user")
	if err == nil {
		t.Error("admin-0 NÃO deveria poder alterar o role de outro admin")
	}

	// Tenta alterar role de user1 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "user1", "admin")
	if err != nil {
		t.Errorf("full_admin deveria poder alterar o role de outro usuário: %v", err)
	}

	// Tenta remover role admin de admin-0 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "admin-0", "user")
	if err != nil {
		t.Errorf("full_admin deveria poder remover o role admin de outro admin: %v", err)
	}

	// Confere se user1 virou admin
	users, err := userStore.ListUsers()
	if err != nil {
		t.Fatalf("Erro ao listar usuários: %v", err)
	}
	var user1, admin0 domain.User
	for _, u := range users {
		if u.Username == "user1" {
			user1 = u
		}
		if u.Username == "admin-0" {
			admin0 = u
		}
	}
	if user1.Role != "admin" {
		t.Error("user1 deveria ser admin após alteração feita por full_admin")
	}
	if admin0.Role != "user" {
		t.Error("admin-0 NÃO deveria ser admin após remoção feita por full_admin")
	}
}
