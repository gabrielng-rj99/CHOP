package server

import (
	"errors"
	"fmt"
	"time"

	"Open-Generic-Hub/backend/config"
	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"

	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims define o payload do token
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// getGlobalSecret gets the global secret from configuration
func getGlobalSecret() []byte {
	cfg := config.GetConfig()
	return []byte(cfg.JWT.SecretKey)
}

// Gera a chave de assinatura dinâmica para o usuário
func getUserSigningKey(user *domain.User) ([]byte, error) {
	if user == nil || user.AuthSecret == "" {
		return nil, errors.New("auth_secret do usuário não disponível")
	}
	return append(getGlobalSecret(), []byte(user.AuthSecret)...), nil
}

// Gera um JWT para o usuário autenticado
func GenerateJWT(user *domain.User) (string, error) {
	signingKey, err := getUserSigningKey(user)
	if err != nil {
		return "", err
	}

	cfg := config.GetConfig()
	claims := JWTClaims{
		UserID:   user.ID,
		Username: derefString(user.Username),
		Role:     derefString(user.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(cfg.JWT.ExpirationTime) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// ========== REFRESH TOKEN ==========

type RefreshTokenClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// Gera um refresh token para o usuário autenticado
func GenerateRefreshToken(user *domain.User) (string, error) {
	signingKey, err := getUserSigningKey(user)
	if err != nil {
		return "", err
	}

	cfg := config.GetConfig()
	claims := RefreshTokenClaims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(cfg.JWT.RefreshExpirationTime) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// Valida o refresh token e retorna as claims se válido
func ValidateRefreshToken(tokenString string, userStore *store.UserStore) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*RefreshTokenClaims)
		if !ok {
			return nil, errors.New("formato de claims inválido")
		}
		// Buscar usuário no banco
		user, err := userStore.GetUserByID(claims.UserID)
		if err != nil || user == nil || user.AuthSecret == "" {
			return nil, errors.New("usuário não encontrado ou auth_secret ausente")
		}
		return getUserSigningKey(user)
	})

	if err != nil {
		return nil, fmt.Errorf("refresh token inválido: %w", err)
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("refresh token inválido ou expirado")
	}

	return claims, nil
}

// Valida o JWT e retorna as claims se válido
func ValidateJWT(tokenString string, userStore *store.UserStore) (*JWTClaims, error) {
	// Primeiro, parse o token sem validar assinatura para extrair o user_id
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			return nil, errors.New("formato de claims inválido")
		}
		// Buscar usuário no banco
		user, err := userStore.GetUserByID(claims.UserID)
		if err != nil || user == nil || user.AuthSecret == "" {
			return nil, errors.New("usuário não encontrado ou auth_secret ausente")
		}
		return getUserSigningKey(user)
	})

	if err != nil {
		return nil, fmt.Errorf("token inválido: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token inválido ou expirado")
	}

	return claims, nil
}

// Helper para desreferenciar ponteiros de string
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Extrai o token do header Authorization
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

// Extrai e valida as claims do JWT no request
func getClaimsFromRequest(r *http.Request, userStore *store.UserStore) (*JWTClaims, error) {
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		return nil, errors.New("token não fornecido")
	}

	claims, err := ValidateJWT(tokenString, userStore)
	if err != nil {
		return nil, errors.New("token inválido ou expirado")
	}

	return claims, nil
}
