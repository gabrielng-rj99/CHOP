package main

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwtKey é a chave secreta para assinar JWT
// Em produção, DEVE ser carregada de uma variável de ambiente
// Exemplo: jwtKey = []byte(os.Getenv("JWT_SECRET"))
// NUNCA coloque a chave secreta em código-fonte!
var jwtKey = []byte("sua-chave-secreta-super-segura-mude-em-producao-use-variavel-de-ambiente")

type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID, username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func ValidateJWT(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func extractTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func getClaimsFromRequest(r *http.Request) (*JWTClaims, error) {
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		return nil, errors.New("token não fornecido")
	}

	claims, err := ValidateJWT(tokenString)
	if err != nil {
		log.Printf("Erro ao validar token: %v", err)
		return nil, errors.New("token inválido ou expirado")
	}

	return claims, nil
}
