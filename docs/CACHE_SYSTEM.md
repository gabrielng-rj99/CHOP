# Sistema de Cache - Entity Hub

## Visão Geral

O Entity Hub implementa um sistema de cache robusto no frontend para reduzir a quantidade de requisições ao servidor e melhorar a performance da aplicação. Este sistema trabalha em conjunto com o rate limiting do backend para garantir uma experiência fluida ao usuário.

## Configuração do Backend

### Rate Limiting

O backend possui rate limiting configurável através de variáveis de ambiente:

- `RATE_LIMIT`: Número de requisições por segundo (padrão: 5)
- `RATE_BURST`: Número máximo de requisições em burst (padrão: 10)

Para ajustar o rate limiting em ambiente de desenvolvimento, você pode definir valores maiores:

```bash
export RATE_LIMIT=100
export RATE_BURST=200
```

**Nota**: Em produção, mantenha valores conservadores para proteger o servidor contra abuso.

## Arquitetura do Cache no Frontend

### Componentes Principais

#### 1. CacheManager (`frontend/src/utils/cacheManager.js`)

Gerenciador singleton de cache com as seguintes funcionalidades:

- **TTL (Time To Live)**: Cache expira automaticamente após 5 minutos (configurável)
- **Invalidação por padrão**: Permite invalidar múltiplas entradas de uma vez
- **Limpeza automática**: Remove entradas expiradas a cada 10 minutos
- **Geração de chaves**: Cria chaves únicas baseadas em endpoint e parâmetros

#### 2. DataContext (`frontend/src/contexts/DataContext.jsx`)

Contexto React que centraliza todas as operações de dados:

- **Deduplicação de requisições**: Evita múltiplas chamadas simultâneas para o mesmo endpoint
- **Cache transparente**: Verifica cache antes de fazer requisições
- **Invalidação automática**: Limpa cache após operações de modificação (create, update, delete)
- **Refresh forçado**: Permite ignorar cache quando necessário

### Métodos do DataContext

#### Leitura de Dados (com cache)

```javascript
const { fetchAgreements, fetchEntities, fetchCategories, fetchSubcategories } = useData();

// Busca com cache (usa cache se disponível)
const data = await fetchAgreements();

// Força refresh (ignora cache)
const freshData = await fetchAgreements({}, true);
```

#### Operações de Modificação (invalidam cache)

```javascript
const { createAgreement, updateAgreement, deleteAgreement } = useData();

// Cria novo acordo e invalida cache automaticamente
await createAgreement(data);

// Atualiza acordo e invalida cache automaticamente
await updateAgreement(id, data);

// Deleta acordo e invalida cache automaticamente
await deleteAgreement(id);
```

#### Invalidação Manual

```javascript
const { invalidateCache } = useData();

// Invalida todo o cache de agreements
invalidateCache('agreements');

// Invalida todo o cache
invalidateCache();
```

## Integração nos Componentes

### Dashboard

O Dashboard utiliza cache para todas as operações de leitura:

```javascript
// Carregamento inicial (usa cache)
useEffect(() => {
    loadData();
}, []);

// Botão de atualizar (força refresh)
<button onClick={() => loadData(true)}>
    🔄 Atualizar Dados
</button>
```

### Agreements (Contratos)

```javascript
// Carregamento inicial
const loadInitialData = async (forceRefresh = false) => {
    await Promise.all([
        loadAgreements(forceRefresh),
        loadEntities(forceRefresh),
        loadCategories(forceRefresh),
    ]);
};

// Após criar/atualizar/deletar
const handleCreateContract = async () => {
    await agreementsApi.createAgreement(...);
    invalidateCache('agreements');
    await loadAgreements(true); // Force refresh
};
```

### Entities (Clientes)

Similar aos Agreements, com invalidação automática após modificações.

## Benefícios do Sistema de Cache

### 1. Redução de Requisições

- **Navegação**: Ao voltar para uma página já visitada, os dados são carregados instantaneamente do cache
- **React StrictMode**: Em desenvolvimento, o React monta componentes duas vezes. O cache evita requisições duplicadas
- **Múltiplos componentes**: Se vários componentes precisam dos mesmos dados, apenas uma requisição é feita

### 2. Melhor Performance

- **Carregamento instantâneo**: Dados em cache aparecem imediatamente
- **Menos carga no servidor**: Reduz drasticamente o número de requisições
- **Experiência do usuário**: Interface mais responsiva

### 3. Proteção contra Rate Limiting

- **Evita 429 errors**: Cache reduz drasticamente requisições, evitando atingir o rate limit
- **Deduplicação**: Previne requisições duplicadas simultâneas
- **Refresh controlado**: Usuário decide quando buscar dados frescos

## Estratégias de Cache

### Cache Automático

Por padrão, todas as requisições GET são cacheadas por 5 minutos:

```javascript
// Primeira chamada: vai ao servidor
const data1 = await fetchEntities();

// Segunda chamada (dentro de 5 minutos): retorna do cache
const data2 = await fetchEntities(); // Instantâneo!
```

### Invalidação Inteligente

O cache é invalidado automaticamente após modificações:

```javascript
// Criar entidade
await createEntity(data);
// Cache de 'entities' é automaticamente invalidado

// Próxima leitura vai buscar dados frescos
const freshData = await fetchEntities();
```

### Refresh Manual

Botões de "Atualizar" permitem ao usuário buscar dados frescos:

```javascript
<button onClick={() => loadData(true)}>
    🔄 {loading ? "Atualizando..." : "Atualizar"}
</button>
```

## Monitoramento e Debug

### Estatísticas do Cache

```javascript
const { getCacheStats } = useData();

const stats = getCacheStats();
console.log('Entradas em cache:', stats.entries);
console.log('Chaves:', stats.keys);
```

### Debug no Console

O CacheManager registra operações importantes:

```javascript
// No console do navegador
cacheManager.getStats() // Ver estatísticas
cacheManager.cache.keys() // Ver todas as chaves
```

## Boas Práticas

### 1. Use o DataContext

❌ **Não faça assim:**
```javascript
const response = await fetch(`${apiUrl}/entities`);
```

✅ **Faça assim:**
```javascript
const { fetchEntities } = useData();
const response = await fetchEntities();
```

### 2. Invalide Cache após Modificações

❌ **Não faça assim:**
```javascript
await createEntity(data);
await loadEntities(); // Pode retornar dados antigos do cache
```

✅ **Faça assim:**
```javascript
await createEntity(data); // Já invalida automaticamente
await loadEntities(true); // Force refresh
```

### 3. Use Force Refresh em Botões de Atualizar

```javascript
<button onClick={() => loadData(true)}>
    Atualizar
</button>
```

### 4. Não Force Refresh Desnecessariamente

❌ **Evite:**
```javascript
// Sempre forçar refresh desperdiça o cache
useEffect(() => {
    loadData(true);
}, []);
```

✅ **Prefira:**
```javascript
// Deixe o cache trabalhar
useEffect(() => {
    loadData(); // Usa cache se disponível
}, []);
```

## Configuração Avançada

### Ajustar TTL (Time To Live)

Para alterar o tempo de vida do cache, edite `cacheManager.js`:

```javascript
constructor() {
    this.defaultTTL = 5 * 60 * 1000; // 5 minutos
    // Altere para o valor desejado
}
```

### Desabilitar Cache Temporariamente

Para debug ou testes:

```javascript
// No console do navegador
cacheManager.clearAll(); // Limpa todo o cache
cacheManager.defaultTTL = 0; // Desabilita cache (não recomendado)
```

## Troubleshooting

### Problema: Ainda recebendo 429 (Too Many Requests)

**Solução 1**: Verifique se está usando o DataContext em todos os componentes

**Solução 2**: Aumente o rate limit no backend (desenvolvimento):
```bash
export RATE_LIMIT=100
export RATE_BURST=200
```

**Solução 3**: Verifique se há requisições duplicadas no React StrictMode

### Problema: Dados desatualizados

**Solução 1**: Use o botão "Atualizar" para forçar refresh

**Solução 2**: Verifique se a invalidação de cache está ocorrendo após modificações

**Solução 3**: Reduza o TTL do cache se necessário

### Problema: Cache crescendo muito

O sistema possui limpeza automática, mas você pode limpar manualmente:

```javascript
cacheManager.cleanup(); // Remove entradas expiradas
cacheManager.clearAll(); // Remove tudo
```

## Exemplos Práticos

### Exemplo 1: Carregar Dados com Cache

```javascript
import { useData } from '../contexts/DataContext';

function MyComponent() {
    const { fetchEntities, loading, errors } = useData();
    const [entities, setEntities] = useState([]);

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async (forceRefresh = false) => {
        try {
            const response = await fetchEntities({}, forceRefresh);
            setEntities(response.data || []);
        } catch (error) {
            console.error('Error loading entities:', error);
        }
    };

    return (
        <div>
            <button onClick={() => loadData(true)}>
                🔄 Atualizar
            </button>
            {/* Renderizar entities */}
        </div>
    );
}
```

### Exemplo 2: Criar e Invalidar Cache

```javascript
import { useData } from '../contexts/DataContext';

function CreateEntityForm() {
    const { createEntity, fetchEntities } = useData();

    const handleSubmit = async (formData) => {
        try {
            // Cria entidade (invalida cache automaticamente)
            await createEntity(formData);
            
            // Busca dados frescos
            await fetchEntities({}, true);
            
            // Fechar modal, limpar form, etc.
        } catch (error) {
            console.error('Error creating entity:', error);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            {/* Form fields */}
        </form>
    );
}
```

## Conclusão

O sistema de cache do Entity Hub foi projetado para ser:

- **Transparente**: Funciona automaticamente sem configuração adicional
- **Inteligente**: Invalida cache quando necessário
- **Seguro**: Protege contra rate limiting
- **Performático**: Reduz drasticamente o número de requisições

Use o DataContext para todas as operações de dados e deixe o sistema de cache trabalhar por você!