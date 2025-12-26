# Quick Start: Sistema de Cache

## TL;DR - Início Rápido

### 1. Ajuste o Rate Limiting (Desenvolvimento)

```bash
# Aumente os limites para desenvolvimento
export RATE_LIMIT=100
export RATE_BURST=200

# Inicie o backend
./ehop-backend-dev
```

### 2. O Cache Já Está Funcionando! 🎉

O sistema de cache está **automaticamente ativo** em todos os componentes que usam o `DataContext`. Você não precisa fazer nada extra!

### 3. Use nos Seus Componentes

```javascript
import { useData } from '../contexts/DataContext';

function MyComponent() {
    const { fetchEntities } = useData();
    const [data, setData] = useState([]);
    
    useEffect(() => {
        loadData();
    }, []);
    
    const loadData = async (forceRefresh = false) => {
        const response = await fetchEntities({}, forceRefresh);
        setData(response.data || []);
    };
    
    return (
        <div>
            <button onClick={() => loadData(true)}>
                🔄 Atualizar
            </button>
            {/* Seu conteúdo */}
        </div>
    );
}
```

## Como Funciona

### Carregamento Automático com Cache

```javascript
// 1ª vez: busca do servidor (leva ~100ms)
const data1 = await fetchEntities();

// 2ª vez: retorna do cache (instantâneo!)
const data2 = await fetchEntities();
```

### Refresh Manual

```javascript
// Botão de atualizar: força busca nova do servidor
<button onClick={() => loadData(true)}>
    🔄 Atualizar
</button>
```

### Invalidação Automática

```javascript
// Ao criar/atualizar/deletar, cache é limpo automaticamente
await createEntity(newData);  // Cache invalidado!
await fetchEntities();        // Busca dados frescos
```

## Benefícios Imediatos

✅ **Sem 429 errors**: Cache reduz 90% das requisições  
✅ **Carregamento instantâneo**: Dados aparecem na hora  
✅ **Menos carga no servidor**: Servidor agradece  
✅ **Melhor UX**: Interface mais responsiva  

## Problemas Comuns

### Ainda recebendo 429?

1. **Verifique se está usando o DataContext**:
   ```javascript
   ❌ const res = await fetch(`${apiUrl}/entities`);
   ✅ const res = await fetchEntities();
   ```

2. **Aumente o rate limit** (desenvolvimento):
   ```bash
   export RATE_LIMIT=100
   export RATE_BURST=200
   ```

3. **Não force refresh desnecessariamente**:
   ```javascript
   ❌ useEffect(() => loadData(true), []); // Sempre força
   ✅ useEffect(() => loadData(), []);     // Usa cache
   ```

### Dados desatualizados?

Use o botão "Atualizar" ou force refresh:
```javascript
loadData(true);  // true = force refresh
```

## Métodos Disponíveis

### Leitura (com cache)
- `fetchAgreements(params, forceRefresh)`
- `fetchEntities(params, forceRefresh)`
- `fetchCategories(forceRefresh)`
- `fetchSubcategories(categoryId, forceRefresh)`

### Escrita (invalida cache automaticamente)
- `createAgreement(data)`
- `updateAgreement(id, data)`
- `deleteAgreement(id)`
- `createEntity(data)`
- `updateEntity(id, data)`
- `deleteEntity(id)`
- `createCategory(data)`
- `updateCategory(id, data)`
- `deleteCategory(id)`

### Utilitários
- `invalidateCache(resource)` - Limpa cache manualmente
- `getCacheStats()` - Estatísticas do cache

## Configuração do TTL

Por padrão, cache expira em **5 minutos**.

Para alterar, edite `frontend/src/utils/cacheManager.js`:

```javascript
constructor() {
    this.defaultTTL = 5 * 60 * 1000; // 5 minutos
    // Altere para o valor desejado
}
```

## Debug

### Ver estatísticas do cache

```javascript
// No console do navegador
const { getCacheStats } = useData();
console.log(getCacheStats());
```

### Limpar todo o cache

```javascript
import cacheManager from '../utils/cacheManager';

// No console do navegador
cacheManager.clearAll();
```

### Verificar chaves em cache

```javascript
import cacheManager from '../utils/cacheManager';

// No console do navegador
console.log(Array.from(cacheManager.cache.keys()));
```

## Checklist de Implementação

Para adicionar cache em um novo componente:

- [ ] Importar `useData` do DataContext
- [ ] Usar métodos `fetch*` ao invés de `fetch()` direto
- [ ] Adicionar botão "Atualizar" com `forceRefresh=true`
- [ ] Invalidar cache após create/update/delete
- [ ] Testar carregamento e refresh

## Exemplo Completo

```javascript
import React, { useState, useEffect } from 'react';
import { useData } from '../contexts/DataContext';

export default function MyPage() {
    const {
        fetchEntities,
        createEntity,
        updateEntity,
        deleteEntity,
        invalidateCache,
        loading,
        errors
    } = useData();
    
    const [entities, setEntities] = useState([]);
    const [formData, setFormData] = useState({});
    
    useEffect(() => {
        loadData();
    }, []);
    
    const loadData = async (forceRefresh = false) => {
        try {
            const response = await fetchEntities({}, forceRefresh);
            setEntities(response.data || []);
        } catch (error) {
            console.error('Error:', error);
        }
    };
    
    const handleCreate = async () => {
        try {
            await createEntity(formData);
            // Cache já foi invalidado automaticamente!
            await loadData(true); // Força refresh
        } catch (error) {
            console.error('Error:', error);
        }
    };
    
    const handleUpdate = async (id) => {
        try {
            await updateEntity(id, formData);
            await loadData(true);
        } catch (error) {
            console.error('Error:', error);
        }
    };
    
    const handleDelete = async (id) => {
        try {
            await deleteEntity(id);
            await loadData(true);
        } catch (error) {
            console.error('Error:', error);
        }
    };
    
    return (
        <div>
            <h1>My Page</h1>
            
            {/* Botão de refresh */}
            <button 
                onClick={() => loadData(true)}
                disabled={loading['/entities']}
            >
                🔄 {loading['/entities'] ? 'Atualizando...' : 'Atualizar'}
            </button>
            
            {/* Lista de entidades */}
            {entities.map(entity => (
                <div key={entity.id}>
                    {entity.name}
                    <button onClick={() => handleUpdate(entity.id)}>
                        Editar
                    </button>
                    <button onClick={() => handleDelete(entity.id)}>
                        Deletar
                    </button>
                </div>
            ))}
            
            {/* Form de criação */}
            <button onClick={handleCreate}>
                Criar Novo
            </button>
        </div>
    );
}
```

## Próximos Passos

1. ✅ Sistema de cache implementado
2. ✅ DataContext criado e integrado
3. ✅ Dashboard, Agreements e Entities atualizados
4. 📝 Documentação completa criada

Para mais detalhes, consulte:

- [CACHE_SYSTEM.md](./CACHE_SYSTEM.md) - Documentação completa do cache
- [RATE_LIMITING.md](./RATE_LIMITING.md) - Configuração de rate limiting

## Suporte

Se encontrar problemas:

1. Verifique os logs do browser (F12)
2. Verifique os logs do backend
3. Consulte a documentação completa
4. Teste com rate limit aumentado em desenvolvimento

---

**Dica**: O cache funciona melhor quando você deixa ele trabalhar. Não force refresh a menos que seja necessário! 🚀