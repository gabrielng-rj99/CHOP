# Documentação dos Testes - Store

Esta documentação descreve os testes implementados para validar as regras de negócio e garantir a integridade dos dados no sistema de gerenciamento de licenças.

## Estrutura dos Testes

Os testes estão organizados em três principais componentes:

1. ClientStore (client_test.go)
2. EntityStore (entity_test.go)
3. LicenseStore (licenses_test.go)

## ClientStore Tests

### TestCreateClient
Valida a criação de empresas com os seguintes cenários:

- **Sucesso - Criação Normal**
  - Verifica se uma empresa é criada com todos os campos obrigatórios
  - Valida a geração de ID
  - Garante que o CNPJ e nome são preenchidos

- **Erro - CNPJ Duplicado**
  - Verifica se o sistema impede a criação de duas empresas com o mesmo CNPJ
  - Valida a constraint UNIQUE do banco de dados
  - Garante a unicidade do CNPJ no sistema

- **Erro - CNPJ Inválido**
  - Verifica se o sistema rejeita CNPJs com formato inválido
  - Valida o formato do CNPJ antes da persistência

### TestArchiveClient
Testa o arquivamento (soft delete) de empresas:

- **Sucesso - Arquivamento Normal**
  - Verifica se uma empresa é arquivada corretamente
  - Valida o preenchimento do campo archived_at

- **Erro - Empresa com Licenças Ativas**
  - Impede o arquivamento de empresas que possuem licenças em vigor
  - Garante a integridade dos dados relacionados

### TestDeleteClientPermanently
Testa a deleção permanente de empresas:

- **Sucesso - Deleção Normal**
  - Verifica a remoção completa dos registros
  - Valida o cascade delete nas unidades e licenças

## EntityStore Tests

### TestCreateEntity
Valida a criação de unidades:

- **Sucesso - Criação Normal**
  - Verifica se uma unidade é criada com todos os campos obrigatórios
  - Valida o vínculo com a empresa

- **Erro - Empresa Não Existe**
  - Impede a criação de unidades para empresas inexistentes
  - Valida a integridade referencial

### TestUpdateEntity
Testa a atualização de unidades:

- **Sucesso - Atualização Normal**
  - Permite atualização do nome da unidade
  
- **Erro - Alteração de Client ID**
  - Impede a mudança de vínculo com empresa
  - Garante a integridade dos relacionamentos

### TestDeleteEntity
Testa a deleção de unidades:

- **Sucesso - Deleção Normal**
  - Verifica a remoção da unidade

- **Erro - Unidade com Licenças Ativas**
  - Impede a deleção de unidades que possuem licenças vigentes
  - Protege dados importantes do sistema

## LicenseStore Tests

### TestCreateLicense
Valida a criação de licenças:

- **Sucesso - Criação Normal**
  - Verifica criação com todos os campos obrigatórios
  - Valida datas de início e fim

- **Sucesso - Com Unidade**
  - Testa criação de licença vinculada a uma unidade
  - Valida o relacionamento unidade-empresa

- **Erro - Empresa Arquivada**
  - Impede criação de licenças para empresas arquivadas
  - Valida o status da empresa

- **Erro - Tipo Não Existe**
  - Verifica a existência do tipo de licença
  - Garante integridade referencial

- **Erro - Licença Sobreposta**
  - Impede sobreposição de licenças do mesmo tipo para mesma empresa/unidade
  - Garante unicidade temporal das licenças

### TestGetLicensesByClientID
Testa a busca de licenças por empresa:

- **Sucesso - Licenças Encontradas**
  - Lista todas as licenças de uma empresa
  - Filtra apenas empresas não arquivadas

### TestGetLicensesExpiringSoon
Valida a busca de licenças próximas do vencimento:

- **Sucesso - Licenças Encontradas**
  - Lista licenças que expiram em X dias
  - Auxilia no controle de renovações

## MockDB

O sistema de mock foi aprimorado para suportar:

- Queries customizadas para diferentes cenários
- Contagem de registros retornados
- Mensagens de erro personalizadas
- Simulação de diferentes estados do banco

## Cobertura de Regras de Negócio

Os testes garantem as seguintes regras:

1. **Empresas**
   - CNPJ único e válido
   - Não podem ser arquivadas com licenças ativas
   - Soft delete para manter histórico

2. **Unidades**
   - Vínculo permanente com empresa
   - Proteção contra deleção com licenças ativas
   - Validação de existência da empresa

3. **Licenças**
   - Datas válidas e não sobrepostas
   - Vínculo correto com empresa/unidade
   - Controle de status e vencimento
   - Proteção contra empresas arquivadas

## Execução dos Testes

Para executar os testes:

```bash
go test ./tests/store -v
```

Para verificar a cobertura:

```bash
go test ./tests/store -cover
```
