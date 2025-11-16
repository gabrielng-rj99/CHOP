# Audit Logs - Quick Start Guide

## Visão Rápida

O sistema de auditoria rastreia **todas as operações** no Contract Manager. Apenas `root` pode acessar os logs.

---

## Para Acessar os Logs

1. **Faça login como root**
2. **Clique em "Logs de Auditoria"** no menu lateral
3. **Veja a tabela com todos os logs**

---

## Usando os Filtros

### Filtros Disponíveis:

| Filtro | Opções | Uso |
|--------|--------|-----|
| **Entidade** | user, client, contract, line, category, dependent | Que tipo de coisa foi alterada |
| **Operação** | create, read, update, delete | Que ação foi feita |
| **Status** | success, error | Se funcionou ou falhou |
| **ID da Entidade** | UUID | Buscar histórico de 1 coisa específica |
| **IP Address** | 192.168.1.1 | Quem acessou (de qual máquina) |
| **ID do Admin** | UUID | Que admin fez a operação |
| **Data Inicial** | Data/Hora | Buscar a partir de quando |
| **Data Final** | Data/Hora | Buscar até quando |

### Exemplo: Encontrar todos os usuários deletados

1. **Entidade:** user
2. **Operação:** delete
3. **Status:** success
4. Clique **"Aplicar Filtros"**

---

## Expandindo Logs para Ver Detalhes

Clique no botão **"Detalhes"** em qualquer linha para expandir e ver:

- **Informações da Requisição:** método HTTP, endpoint, tempo de resposta
- **Informações do Cliente:** IP, navegador/app que fez a requisição
- **Valores Alterados:** o que era antes e depois (em JSON)
- **Mensagem de Erro:** se algo deu errado

---

## Paginação

- **Anterior/Próxima:** Navegar entre páginas
- **Ir para página:** Seletor rápido
- **Por página:** Escolher 25, 50, 100 ou 200 logs por página

---

## Exportando Logs

Clique **"Exportar JSON"** para baixar um arquivo JSON com todos os logs (considerando filtros aplicados).

Útil para:
- Análise externa
- Compliance reports
- Integração com ferramentas de segurança

---

## Soft-Delete de Usuários

Quando um usuário é deletado:

1. **No banco:** Ele recebe `deleted_at = NOW()` e dados sensíveis viram NULL
2. **No log:** Fica registrado quem deletou, quando, de qual IP
3. **Integridade:** Não quebra nada - o histórico fica intacto
4. **No frontend:** Mostra como "Deletado" na coluna Admin

---

## Cores e Significados

### Operações:
- 🟢 **Verde** = CREATE (novo registro)
- 🟠 **Laranja** = UPDATE (modificado)
- 🔴 **Vermelho** = DELETE (removido)
- 🔵 **Azul** = READ (consultado)

### Status:
- 🟢 **Verde** = SUCCESS (funcionou)
- 🔴 **Vermelho** = ERROR (falhou)

---

## Casos de Uso Comuns

### 1. Investigar quem deletou um cliente

```
Entidade: client
Operação: delete
Status: success
```

Vai mostrar: quem, quando, de qual IP.

### 2. Ver todas as ações de um admin

```
ID do Admin: [uuid do admin]
```

Mostra tudo que ele fez no sistema.

### 3. Encontrar erros em um período

```
Operação: [deixe vazio]
Status: error
Data Inicial: [data de início]
Data Final: [data de fim]
```

Mostra tudo que falhou naquele período.

### 4. Rastrear modificações de um contrato

```
Entidade: contract
ID da Entidade: [uuid do contrato]
```

Histórico completo do que mudou naquele contrato.

### 5. Análise de segurança - IPs suspeitos

```
IP Address: [IP específico]
```

Ver tudo que foi feito daquele IP.

---

## Dados Capturados em Cada Log

```json
{
  "timestamp": "2024-01-15T14:30:45Z",      // Quando aconteceu
  "operation": "delete",                     // Que ação
  "entity": "user",                          // Qual tipo
  "entity_id": "550e8400-...",              // Qual específico
  "admin_username": "admin1",                // Quem fez
  "status": "success",                       // Funcionou?
  "ip_address": "192.168.1.100",            // De onde
  "user_agent": "Mozilla/5.0...",           // Que navegador
  "request_method": "DELETE",                // HTTP method
  "request_path": "/api/users/...",         // Qual endpoint
  "old_value": { "username": "joao", ... }, // Como era
  "new_value": null                          // Como ficou
}
```

---

## Dicas de Segurança

✅ **Atividade anômala?** Procure por múltiplas deletions ou acessos de IPs novos  
✅ **Admin suspeito?** Filtre por ID do admin e veja todos seus logs  
✅ **Período crítico?** Use data range para investigar eventos específicos  
✅ **Conformidade?** Exporte logs periodicamente como backup  

---

## Limitações e Comportamentos

- **Soft-delete:** Usuários deletados não podem fazer login, mas deixam histórico
- **Apenas leitura:** Os logs de auditoria não podem ser editados ou deletados (integridade garantida)
- **Paginação máxima:** 200 itens por página
- **Histórico completo:** Todos os logs são mantidos (cleanup pode ser configurado no backend)

---

## Troubleshooting

**Não vejo botão "Logs de Auditoria"?**
→ Você não é root. Peça ao administrador.

**Nenhum log aparece?**
→ Talvez não haja operações naquele período/com esses filtros. Limpe filtros e tente novamente.

**A tabela demora a carregar?**
→ Muitos registros. Tente filtrar por data ou entidade específica.

**JSON não abre ao exportar?**
→ Pode abrir em qualquer editor de texto ou importar em Python/JavaScript.

---

## Próximos Passos

- Explore os filtros e combine-os para investigações específicas
- Crie rotinas de revisão de logs periodicamente
- Use exportação para conformidade e auditoria externa
- Compartilhe com o time de segurança quando necessário

---

**Dúvidas?** Consulte a documentação completa em `AUDIT_LOGS_IMPLEMENTATION.md`
