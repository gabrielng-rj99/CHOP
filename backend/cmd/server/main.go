// Licenses-Manager/backend/cmd/server/main.go

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/store"
)

func main() {
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco de dados: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Erro ao fechar a conexão com o banco de dados: %v", err)
		}
	}()
	userStore := store.NewUserStore(db)

	http.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}
		id, err := userStore.CreateUser(req.Username, req.Username, req.Password, "user")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Nunca retorna hash de senha!
		resp := struct {
			ID        string    `json:"id"`
			Username  string    `json:"username"`
			CreatedAt time.Time `json:"created_at"`
		}{
			ID:        id,
			Username:  req.Username,
			CreatedAt: time.Now(),
		}
		w.Header().Set("Content-Line", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}

		// --- Proteção contra brute-force por IP ---
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}

		// Função auxiliar para buscar/atualizar tentativas por IP
		// (Exemplo: você deve implementar a persistência real no banco)
		type IPLock struct {
			FailedAttempts int
			LockLevel      int
			LockedUntil    time.Time
		}
		getIPLock := func(ip string) *IPLock {
			// TODO: Buscar do banco de dados real
			return &IPLock{}
		}
		updateIPLock := func(ip string, lock *IPLock) {
			// TODO: Atualizar no banco de dados real
		}
		bruteForceLevels := []struct {
			attempts int
			duration time.Duration
		}{
			{5, time.Minute},
			{3, 5 * time.Minute},
			{3, 15 * time.Minute},
			{3, 30 * time.Minute},
			{3, 60 * time.Minute},
			{3, 120 * time.Minute},
			{3, 240 * time.Minute},
			{3, 480 * time.Minute},
			{3, 1440 * time.Minute}, // 24h
		}

		ipLock := getIPLock(ip)
		now := time.Now()
		if !ipLock.LockedUntil.IsZero() && now.Before(ipLock.LockedUntil) {
			http.Error(w, fmt.Sprintf("Este IP está bloqueado até %s por múltiplas tentativas. Tente novamente depois.", ipLock.LockedUntil.Format(time.RFC1123)), http.StatusTooManyRequests)
			return
		}

		// Autenticação normal
		user, err := userStore.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			// Falha: incrementa tentativas do IP
			ipLock.FailedAttempts++
			level := ipLock.LockLevel
			if level >= len(bruteForceLevels) {
				ipLock.LockedUntil = now.Add(365 * 24 * time.Hour) // bloqueio manual
			} else {
				limit := bruteForceLevels[level].attempts
				if ipLock.FailedAttempts >= limit {
					ipLock.LockLevel++
					if ipLock.LockLevel >= len(bruteForceLevels) {
						ipLock.LockedUntil = now.Add(365 * 24 * time.Hour)
					} else {
						ipLock.LockedUntil = now.Add(bruteForceLevels[ipLock.LockLevel].duration)
					}
					ipLock.FailedAttempts = 0
				}
			}
			updateIPLock(ip, ipLock)
			http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
			return
		}
		// Sucesso: zera tentativas do IP
		ipLock.FailedAttempts = 0
		ipLock.LockLevel = 0
		ipLock.LockedUntil = time.Time{}
		updateIPLock(ip, ipLock)

		resp := struct {
			ID        string    `json:"id"`
			Username  string    `json:"username"`
			CreatedAt time.Time `json:"created_at"`
		}{
			ID:        user.ID,
			Username:  user.Username,
			CreatedAt: user.CreatedAt,
		}
		w.Header().Set("Content-Line", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	fmt.Println("Servidor rodando em http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
