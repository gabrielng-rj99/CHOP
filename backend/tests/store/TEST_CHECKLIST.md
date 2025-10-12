# Checklist de Testes - Licenses Manager

Este documento serve como guia rápido para garantir que novos recursos implementados sigam os padrões de teste estabelecidos.

## ✅ Checklist Geral

Para cada novo recurso, verifique se os testes cobrem:

### Validações Básicas
- [ ] Campos obrigatórios preenchidos
- [ ] Formatos de dados válidos
- [ ] Tipos de dados corretos
- [ ] Limites de tamanho de campos

### Integridade Referencial
- [ ] Existência de registros relacionados
- [ ] Validação de chaves estrangeiras
- [ ] Consistência entre relacionamentos

### Regras de Negócio
- [ ] Restrições específicas do domínio
- [ ] Validações temporais
- [ ] Regras de estado/status
- [ ] Permissões e acessos

### Tratamento de Erros
- [ ] Casos de erro esperados
- [ ] Mensagens de erro apropriadas
- [ ] Rollback em caso de falhas
- [ ] Logs de erro adequados

## 🎯 Checklist Específico por Entidade

### Companies
- [ ] Validação de CNPJ único
- [ ] Formato de CNPJ válido
- [ ] Verificação de arquivamento
- [ ] Proteção contra deleção com dependências

### Units
- [ ] Vínculo com empresa existente
- [ ] Proteção contra mudança de empresa
- [ ] Validação de deleção segura
- [ ] Unicidade do nome por empresa

### Licenses
- [ ] Datas válidas (início/fim)
- [ ] Não sobreposição temporal
- [ ] Vínculo com empresa ativa
- [ ] Validação de tipo existente
- [ ] Verificação de unidade (se especificada)

## 📝 Padrões de Teste

### Estrutura de Testes
```go
func TestNomeRecurso(t *testing.T) {
    tests := []struct {
        name        string
        input       domain.Type
        mockDB      *MockDB
        expectError bool
        expectID    bool
    }{
        // casos de teste aqui
    }
    // implementação
}
```

### Casos Mínimos
1. Sucesso - caso normal
2. Erro - dados inválidos
3. Erro - violação de regra de negócio
4. Erro - falha no banco

## 🔍 Verificações do MockDB

- [ ] Queries executadas corretamente
- [ ] Parâmetros passados corretamente
- [ ] Comportamento de erro simulado
- [ ] Resultados esperados retornados

## 📊 Cobertura de Testes

Metas de cobertura:
- Statements: > 80%
- Branches: > 75%
- Functions: > 90%
- Lines: > 80%

## 🚀 Como Usar

1. Use este checklist ao implementar novos recursos
2. Marque cada item conforme implementado
3. Documente casos especiais
4. Atualize a documentação de testes

## ⚠️ Considerações Importantes

1. Mantenha os testes independentes
2. Use nomes descritivos para os casos de teste
3. Mantenha o padrão de organização
4. Documente comportamentos não óbvios
5. Atualize o checklist conforme necessário

## 🔄 Processo de Review

Antes do PR:
1. Execute todos os testes
2. Verifique a cobertura
3. Valide contra este checklist
4. Atualize a documentação

Durante o Review:
1. Confirme todos os itens do checklist
2. Verifique casos de borda
3. Valide mensagens de erro
4. Confirme documentação atualizada
