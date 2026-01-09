#!/usr/bin/env python3
import os
import re

# Configuração
BACKEND_ROUTES_FILE = "backend/server/routes.go"
FRONTEND_DIR = "frontend/src"
API_PREFIX_VAR = "${apiUrl}" # Como aparece no JS

def extract_backend_routes():
    """Lê o arquivo routes.go e extrai os padrões de rota registrados."""
    routes = set()
    try:
        with open(BACKEND_ROUTES_FILE, 'r') as f:
            content = f.read()
            # Procura por mux.HandleFunc("/path", ...)
            matches = re.finditer(r'mux\.HandleFunc\("([^"]+)"', content)
            for match in matches:
                route = match.group(1)
                routes.add(route)
    except FileNotFoundError:
        print(f"Erro: Arquivo {BACKEND_ROUTES_FILE} não encontrado.")
        
    return routes

def extract_frontend_api_calls():
    """Varre o diretório frontend e extrai chamadas de API."""
    api_calls = set()
    
    for root, dirs, files in os.walk(FRONTEND_DIR):
        for file in files:
            if file.endswith('.js') or file.endswith('.jsx'):
                path = os.path.join(root, file)
                with open(path, 'r') as f:
                    content = f.read()
                    
                    # 1. Captura chamadas literais '/api/...'
                    literals = re.finditer(r'["\'](/api/[^"\']+)["\']', content)
                    for m in literals:
                        api_calls.add(m.group(1))

                    # 2. Captura template literals com `${apiUrl}`
                    # Ex: `${apiUrl}/contracts`
                    # Regex procura por `${apiUrl}` seguido de path
                    # Assumimos que apiUrl termina sem barra e o path começa com barra, ou vice-versa
                    templates = re.finditer(r'`\$\{apiUrl\}(/[^`]+)`', content)
                    for m in templates:
                        # Normaliza para /api/... assumindo que apiUrl base é /api ou root
                        # No código routes.go, as rotas começam com /api/.
                        # Se apiUrl for '', o path é /contracts (errado).
                        # Se apiUrl for '/api', o path é /api/contracts (certo).
                        # Vamos prefixar com /api para comparação, pois é o padrão esperado.
                        
                        relative_path = m.group(1)
                        # Se o path capturado já começa com /api (raro se usar apiUrl), preserva.
                        if relative_path.startswith("/api/"):
                             call = relative_path
                        else:
                             call = "/api" + relative_path
                             
                        # Substitui interpolação ${...} por {var}
                        call = re.sub(r'\$\{[^}]+\}', '{var}', call)
                        api_calls.add(call)
                        
    return api_calls

def check_consistency():
    print("🔍 Iniciando verificação de consistência de API (Frontend <-> Backend)...")
    
    backend_routes = extract_backend_routes()
    frontend_calls = extract_frontend_api_calls()
    
    print(f"Backend define {len(backend_routes)} rotas base.")
    print(f"Frontend faz chamadas para {len(frontend_calls)} rotas distintas.")
    
    issues = []
    
    # Validação: Para cada chamada do frontend, deve haver uma rota backend que a atenda.
    for call in frontend_calls:
        # Remove query params
        call_clean = call.split('?')[0]
        
        matched = False
        
        for route in backend_routes:
            # 1. Match exato
            if route == call_clean:
                matched = True
                break
            
            # 2. Match de prefixo (para rotas backend terminadas em /)
            # Ex: Backend /api/users/ atende Call /api/users/{var} e /api/users/{var}/block
            if route.endswith('/'):
                if call_clean.startswith(route):
                    matched = True
                    break
                    
                # Caso especial: Call /api/users deve dar match em Backend /api/users/ ?
                # Em Go mux, geralmente sim ou redireciona. Vamos aceitar.
                if call_clean + '/' == route:
                    matched = True
                    break
        
        if not matched:
            issues.append(f"❌ Rota Órfã: Frontend chama '{call_clean}' mas o Backend não exporta rota base para isso.")

    if issues:
        print("\n⚠️  Problemas Encontrados:")
        for issue in sorted(issues):
            print(issue)
        print("\nRecomendação: Verifique se as rotas no routes.go cobrem esses caminhos.")
        return False
    else:
        print("\n✅ Sucesso: Todas as chamadas de API do Frontend parecem ter correspondência no Backend.")
        return True

if __name__ == "__main__":
    if not check_consistency():
        exit(1)
