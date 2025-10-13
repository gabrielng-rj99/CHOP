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
		_, err := userStore.CreateUser(req.Username, req.Username, req.Password, "user")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Autentica para retornar dados do usuário criado
		user, err := userStore.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			http.Error(w, "Usuário criado, mas erro ao autenticar para resposta", http.StatusInternalServerError)
			return
		}
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
