# Deploy Manager - Modular Code Structure

Este documento explica a estrutura modular do Deploy Manager CLI.

## Arquitetura de Arquivos

```
cmd/
├── main.go                      # Menu principal de seleção de modo
├── helpers.go                   # Funções auxiliares compartilhadas
│
├── docker_mode.go               # Menu do Docker Mode
├── docker_operations.go         # Todas operações Docker
│                                # - dockerStartAll(), dockerStopAll(), etc.
│                                # - dockerStartDatabase(), dockerStopDatabase(), etc.
│                                # - dockerStartBackend(), dockerStopBackend(), etc.
│                                # - dockerStartFrontend(), dockerStopFrontend(), etc.
│                                # - dockerLogsAll(), dockerLogsDatabase(), etc.
│
├── monolith_mode.go             # Menu do Monolith Mode
├── monolith_operations.go       # Todas operações Monolith
│                                # - monolithStartAll(), monolithStopAll(), etc.
│                                # - monolithStartDatabase(), monolithStopDatabase(), etc.
│                                # - monolithStartBackend(), monolithStopBackend(), etc.
│                                # - monolithStartFrontend(), monolithStopFrontend(), etc.
│                                # - monolithLogsAll(), monolithLogsDatabase(), etc.
│
├── utilities_mode.go            # Menu de Utilities
└── utilities_operations.go      # Todas operações Utilities
                                # - healthCheckDatabase(), healthCheckBackend(), etc.
                                # - diagnosticsDBSeparation(), diagnosticsConfiguration(), etc.
                                # - testingUnit(), testingIntegration(), etc.
                                # - reportCodeCoverage(), reportPerformance(), etc.
```

## Descrição de Cada Arquivo

### `main.go` (48 linhas)
**Responsabilidade:** Menu principal de entrada
- Apresenta as 3 opções principais (Docker, Monolith, Utilities)
- Roteia para os menus corretos
- Loop infinito até o usuário escolher sair

### `helpers.go` (154 linhas)
**Responsabilidade:** Funções compartilhadas por todos os módulos
- `clearTerminal()` - Limpar a tela
- `waitForEnter()` - Aguardar que usuário pressione Enter
- `getProjectRoot()` - Encontrar diretório raiz do projeto
- `runDockerCompose()` - Executar comandos Docker Compose (detecta automaticamente docker compose vs docker-compose)
- `runCommand()` - Executar comando em diretório específico
- `printSuccess()`, `printError()`, `printWarning()`, etc. - Exibir mensagens formatadas
- `confirmAction()`, `inputPrompt()` - Interação com usuário

### `docker_mode.go` (127 linhas)
**Responsabilidade:** Menu do Docker Mode
- Exibe o menu com todas opções Docker
- Roteia para funções de operações Docker
- Mantém loop até usuário voltar ao menu principal

### `docker_operations.go` (276 linhas)
**Responsabilidade:** Todas operações Docker
- `dockerStartAll()` - Iniciar todos os serviços
- `dockerStopAll()` - Parar todos os serviços
- `dockerRestartAll()` - Reiniciar todos os serviços
- `dockerStatus()` - Exibir status
- `dockerStartDatabase()`, `dockerStopDatabase()`, `dockerRestartDatabase()`, `dockerCleanDatabase()`
- `dockerStartBackend()`, `dockerStopBackend()`, `dockerRestartBackend()`
- `dockerStartFrontend()`, `dockerStopFrontend()`, `dockerRestartFrontend()`
- `dockerLogsAll()`, `dockerLogsDatabase()`, `dockerLogsBackend()`, `dockerLogsFrontend()`
- `dockerCleanAll()` - Parar e limpar tudo

### `monolith_mode.go` (120 linhas)
**Responsabilidade:** Menu do Monolith Mode
- Similar ao Docker Mode mas para serviços em host
- Exibe o menu com todas opções Monolith
- Roteia para funções de operações Monolith

### `monolith_operations.go` (280 linhas)
**Responsabilidade:** Todas operações Monolith
- Funções para iniciar/parar/reiniciar cada serviço individualmente
- Funções para operações em massa (startAll, stopAll, etc.)
- Atualmente com placeholders [PLACEHOLDER] para implementação
- Mesma estrutura que Docker mas adaptada para serviços em host

### `utilities_mode.go` (100 linhas)
**Responsabilidade:** Menu de Utilities
- Exibe menu com categorias: Health Checks, Diagnostics, Testing, Reports
- Roteia para funções de utilidades

### `utilities_operations.go` (290 linhas)
**Responsabilidade:** Todas operações Utilities
- **Health Checks:** `healthCheckDatabase()`, `healthCheckBackend()`, `healthCheckFrontend()`, `healthCheckFull()`
- **Diagnostics:** `diagnosticsDBSeparation()`, `diagnosticsConfiguration()`, `diagnosticsFullSystem()`
- **Testing:** `testingUnit()`, `testingIntegration()`, `testingSecurity()`, `testingAll()`
- **Reporting:** `reportCodeCoverage()`, `reportPerformance()`, `reportDatabaseSchema()`, `reportSystemRequirements()`
- Atualmente com placeholders [PLACEHOLDER] para implementação

## Padrão de Organização

### Organização por Módulo (Mode/Feature)
1. **Um arquivo para menu** (`*_mode.go`)
   - Exibe interface de usuário
   - Roteia para operações

2. **Um arquivo para operações** (`*_operations.go`)
   - Implementa funções relacionadas
   - Mantém tudo junto e fácil de encontrar

### Nomeação de Funções
- `dockerStartAll()` - Docker + operação + escopo
- `monolithStartDatabase()` - Monolith + operação + componente
- `healthCheckBackend()` - Categoria + tipo + componente

### Importações
Todos os arquivos usam apenas `"fmt"`, `"os"`, `"os/exec"`, `"bufio"`, `"strings"`, `"time"`, `"path/filepath"`, `"runtime"`.
Sem dependências externas!

## Como Adicionar Novas Funcionalidades

### Adicionando um novo componente Docker (ex: Redis)
1. Adicione funções ao `docker_operations.go`:
   ```go
   func dockerStartRedis() { ... }
   func dockerStopRedis() { ... }
   func dockerRestartRedis() { ... }
   ```

2. Adicione entradas ao menu em `docker_mode.go`:
   ```go
   case "35":
       dockerStartRedis()
   ```

### Adicionando nova categoria de Utilities
1. Crie arquivo: `utilities_<category>.go`
2. Implemente as funções
3. Adicione ao menu em `utilities_mode.go`

### Adicionando novo modo completamente
1. Crie `<mode>_mode.go` (menu)
2. Crie `<mode>_operations.go` (operações)
3. Adicione ao switch principal em `main.go`

## Compilação

```bash
cd deploy
make build
# ou
go build -o bin/deploy-manager ./cmd
```

## Tamanho dos Arquivos

| Arquivo | Linhas | Responsabilidade |
|---------|--------|------------------|
| main.go | ~50 | Menu principal |
| helpers.go | ~154 | Funções compartilhadas |
| docker_mode.go | ~127 | Menu Docker |
| docker_operations.go | ~276 | Operações Docker |
| monolith_mode.go | ~120 | Menu Monolith |
| monolith_operations.go | ~280 | Operações Monolith |
| utilities_mode.go | ~100 | Menu Utilities |
| utilities_operations.go | ~290 | Operações Utilities |
| **TOTAL** | **~1397** | **Código modular e organizado** |

## Fluxo de Execução

```
main()
├── clearTerminal()
├── Exibir menu principal
├── Ler opção
└── Despachar para:
    ├── dockerModeMenu()
    │   ├── Exibir menu Docker
    │   ├── Ler opção
    │   └── Executar função Docker (docker_operations.go)
    │
    ├── monolithModeMenu()
    │   ├── Exibir menu Monolith
    │   ├── Ler opção
    │   └── Executar função Monolith (monolith_operations.go)
    │
    └── utilitiesMenu()
        ├── Exibir menu Utilities
        ├── Ler opção
        └── Executar função Utility (utilities_operations.go)
```

## Vantagens desta Estrutura

✅ **Modular** - Cada arquivo tem responsabilidade clara  
✅ **Escalável** - Fácil adicionar novos modos/componentes  
✅ **Mantível** - Encontrar código é rápido e fácil  
✅ **Testável** - Funções são isoladas e independentes  
✅ **Legível** - Código organizado e bem comentado  
✅ **Zero Dependências** - Apenas stdlib do Go  
✅ **Compilado Rapidamente** - Tempo de build rápido  
✅ **Standalone** - Binary é independente e portável

## Próximos Passos para Implementação

1. **Implementar Monolith** - `monolith_operations.go`
   - Remover [PLACEHOLDER] e implementar funções
   - Gerenciar processos (PID, signals, etc.)
   - ~7-11 horas

2. **Implementar Health Checks** - `utilities_operations.go`
   - Testar endpoints
   - Verificar conectividade
   - ~3-4 horas

3. **Implementar Diagnostics** - `utilities_operations.go`
   - Validações de configuração
   - Verificação de requisitos
   - ~3-4 horas

4. **Calibrar Tests** - `utilities_operations.go`
   - Integrar com framework de testes
   - Gerar relatórios
   - ~5-8 horas

5. **Implementar Reports** - `utilities_operations.go`
   - Gerar relatórios HTML
   - Análise de performance
   - ~6-8 horas

