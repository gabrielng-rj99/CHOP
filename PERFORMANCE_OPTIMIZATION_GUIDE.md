# 📊 Guia de Otimização de Performance: APIs e Carregamento de Dados

**Data**: Janeiro 2025  
**Status**: 🔴 CRÍTICO — Financial N+1 não documentado, Categories backend OK mas frontend problemático  
**Ações Urgentes**: Consultar PERFORMANCE_DIAGNOSIS.md para issues identificadas

⚠️ **AVISO**: Este guia descreve padrões de otimização, mas **NÃO cobre os problemas críticos** encontrados em Fase 3. Ver seção "Problemas Não Endereçados" no final.

---

## 🔴 Diagnóstico do Problema Original

### Sintomas Observados
- Dashboard não carrega ou demora muito
- Páginas de lista (ex: Clientes) não escalam
- Cada navegação parecia fazer requisições "burras" (carregamento de TUDO)

### Causa Raiz: Padrão "Fetch Everything, Filter Locally"

```javascript
// ❌ PADRÃO ANTIGO (antipadrão)
const loadClients = async () => {
    // Carrega TODOS os clientes, sem limit/offset/filter
    const response = await fetchClients({});
    const allClients = response.data; // 10k, 100k linhas?
    
    // Filtra TUDO em JavaScript
    const activeClients = allClients.filter(c => !c.archived_at && c.status === 'ativo');
    const inactiveClients = allClients.filter(c => !c.archived_at && c.status === 'inativo');
    // ... mais 5 filtros
    
    // Pagina em JavaScript (depois de carregar tudo)
    const page1 = allClients.slice(0, 20);
};
```

### Impacto no Dashboard Especificamente

```javascript
// ❌ ANTES: Dashboard carregava 4+ requisições sequenciais
useEffect(() => {
    loadData(true); // forceRefresh=true = sempre ignora cache
}, []);

const loadData = async () => {
    // 1️⃣ Fetch ALL contratos (sem limit)
    const contracts = await fetchContracts({});
    
    // 2️⃣ Fetch ALL clientes (sem limit)
    const clients = await fetchClients({});
    
    // 3️⃣ Fetch ALL categorias (sem limit)
    const categories = await fetchCategories();
    
    // 4️⃣+ Para CADA categoria, fetch subcategorias (N+1 problema!)
    const subcategories = await Promise.all(
        categories.map(cat => fetchSubcategories(cat.id))
    );
    
    // Depois filtra TUDO em JavaScript só para números:
    const activeClients = clients.filter(...); // contar
    const inactiveClients = clients.filter(...); // contar
    const archivedClients = clients.filter(...); // contar
    const activeContracts = contracts.filter(...); // contar
    // ... etc
};
```

### Números do Problema

| Cenário | Requisições | Dados Carregados | Tempo Estimado |
|---------|-------------|------------------|---|
| 5k clientes, 10k contratos, 20 categorias com 3 subcategorias | **24 requisições** | ~500KB JSON | 8-15s (sem cache) |
| Mesmo cenário com cache | 4 requisições (se tudo expirou) | ~500KB | 2-5s |
| Dashboard load a cada 5 min | 24 × (60/5) = **288 req/hora** | 144MB/hora | ❌ Insustentável |

---

## ✅ Solução Implementada

### 1️⃣ Estratégia: Three-Tier API Design

```
Tier 1 (Lightweight Counts)
├── GET /api/dashboard/counts          ← 1 query, 1 round-trip
├── GET /api/clients/counts            ← agregações
├── GET /api/contracts/counts          ← (adicionado junto)
└── GET /api/[entity]/counts           ← pattern para outras entidades

Tier 2 (Paged Lists with Filters)
├── GET /api/clients?filter=active&limit=20&offset=0
├── GET /api/contracts?limit=50&offset=0
├── GET /api/categories?limit=100&offset=0
└── Padrão: {data: [...], total: N, limit: L, offset: O}

Tier 3 (Full Entities — rare)
├── GET /api/clients/:id                ← detail view
└── POST /api/clients                   ← create com response
```

### 2️⃣ Implementação Backend

#### A) Criar endpoint de counts (uma query, múltiplos agregados)

```go
// backend/server/dashboard_counts_handlers.go
func (s *Server) handleDashboardCounts(w http.ResponseWriter, r *http.Request) {
    // Fan-out: executa 4 queries em paralelo com goroutines
    var wg sync.WaitGroup
    var mu sync.Mutex
    
    wg.Add(4)
    
    // Query 1: client counts (1 query)
    go func() {
        defer wg.Done()
        counts, err := s.clientStore.GetClientCounts()
        // resultado: {total, active, inactive, archived}
    }()
    
    // Query 2: contract counts (1 query com CASE statements)
    go func() {
        defer wg.Done()
        counts, err := s.contractStore.GetContractCounts(expiringDays)
        // resultado: {total, active, expiring, expired, archived}
    }()
    
    // Query 3: category count (1 query)
    go func() {
        defer wg.Done()
        count, err := s.categoryStore.CountCategories(false)
    }()
    
    // Query 4: subcategory count (1 query)
    go func() {
        defer wg.Done()
        count, err := s.subcategoryStore.CountSubcategories(false)
    }()
    
    wg.Wait()
    
    // Responde TUDO em um JSON
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "data": DashboardCounts{
            Clients:       clientCounts,
            Contracts:     contractCounts,
            Categories:    catCount,
            Subcategories: subCount,
        },
    })
}
```

#### B) Implementar métodos de contagem em cada Store

```go
// Padrão em cada store
type ClientCounts struct {
    Total    int `json:"total"`
    Active   int `json:"active"`
    Inactive int `json:"inactive"`
    Archived int `json:"archived"`
}

func (s *ClientStore) GetClientCounts() (*ClientCounts, error) {
    query := `
        SELECT
            COUNT(*) as total,
            COUNT(CASE WHEN archived_at IS NULL AND status='ativo' THEN 1 END) as active,
            COUNT(CASE WHEN archived_at IS NULL AND status='inativo' THEN 1 END) as inactive,
            COUNT(CASE WHEN archived_at IS NOT NULL THEN 1 END) as archived
        FROM clients
    `
    
    var counts ClientCounts
    if err := s.db.QueryRow(query).Scan(
        &counts.Total, &counts.Active, &counts.Inactive, &counts.Archived,
    ); err != nil {
        return nil, err
    }
    return &counts, nil
}
```

#### C) Implementar paginação + filtros em listas

```go
// Padrão em cada handler
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
    // Parse pagination
    limit, offset := parseLimitOffset(r, 100, 500)
    
    // Parse filters
    filter := r.URL.Query().Get("filter")        // "active", "inactive", "archived", "all"
    search := r.URL.Query().Get("search")        // busca em nome, email, etc
    includeArchived := r.URL.Query().Get("include_archived") != "false"
    
    // Fetch paged data
    clients, err := s.clientStore.ListClientsFilteredPaged(
        filter, search, includeArchived, limit, offset,
    )
    
    // Fetch total count (com mesmos filtros)
    total, err := s.clientStore.CountClientsFiltered(
        filter, search, includeArchived,
    )
    
    // Responde com metadados de paginação
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "data":   clients,
        "total":  total,
        "limit":  limit,
        "offset": offset,
    })
}
```

#### D) Implementar métodos paginados no Store

```go
// Padrão: sempre suportar limit=0 para "return all" (backward compatible)
func (s *ClientStore) ListClientsFilteredPaged(
    filter, search string,
    includeArchived bool,
    limit, offset int,
) ([]domain.Client, error) {
    args := []interface{}{}
    whereClause := buildClientFilterWhere(includeArchived, filter, search, &args)
    
    sqlStatement := `SELECT * FROM clients` + whereClause + ` ORDER BY created_at DESC`
    
    var rows *sql.Rows
    if limit > 0 {
        if offset < 0 { offset = 0 }
        args = append(args, limit, offset)
        sqlStatement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", 
            len(args)-1, len(args))
        rows, err = s.db.Query(sqlStatement, args...)
    } else {
        rows, err = s.db.Query(sqlStatement, args...)
    }
    
    // Scan resultados...
    return clients, nil
}

func (s *ClientStore) CountClientsFiltered(
    filter, search string,
    includeArchived bool,
) (int, error) {
    args := []interface{}{}
    whereClause := buildClientFilterWhere(includeArchived, filter, search, &args)
    query := `SELECT COUNT(*) FROM clients` + whereClause
    
    var count int
    if err := s.db.QueryRow(query, args...).Scan(&count); err != nil {
        return 0, err
    }
    return count, nil
}
```

#### E) Helper para builds WHERE clauses dinâmicos

```go
// Reutilizável entre List e Count (evita duplicação)
func buildClientFilterWhere(
    includeArchived bool, 
    filter, search string, 
    args *[]interface{},
) string {
    clauses := []string{}
    
    // Filtros básicos (sem parâmetros — hardcoded)
    if includeArchived {
        switch strings.ToLower(filter) {
        case "active":
            clauses = append(clauses, 
                "archived_at IS NULL", 
                "status = 'ativo'")
        case "inactive":
            clauses = append(clauses, 
                "archived_at IS NULL", 
                "status = 'inativo'")
        case "archived":
            clauses = append(clauses, "archived_at IS NOT NULL")
        }
    }
    
    // Busca (com parâmetro)
    search = strings.TrimSpace(search)
    if search != "" {
        *args = append(*args, "%"+strings.ToLower(search)+"%")
        placeholder := fmt.Sprintf("$%d", len(*args))
        clauses = append(clauses,
            fmt.Sprintf("(LOWER(name) LIKE %s OR LOWER(email) LIKE %s ...)",
                placeholder, placeholder))
    }
    
    if len(clauses) == 0 {
        return ""
    }
    return " WHERE " + strings.Join(clauses, " AND ")
}
```

---

### 3️⃣ Implementação Frontend

#### A) Dashboard: Two-Phase Loading

```javascript
// ✅ NOVO: Carrega stat cards INSTANT, depois tabs em background
export default function Dashboard() {
    const { fetchDashboardCounts, fetchClients, fetchContracts } = useData();
    
    const [dashCounts, setDashCounts] = useState(null);      // {clients, contracts, categories, subcategories}
    const [countsLoading, setCountsLoading] = useState(true);
    
    const [clients, setClients] = useState([]);              // para tabs (lazy)
    const [contracts, setContracts] = useState([]);          // para tabs (lazy)
    const [dataLoading, setDataLoading] = useState(true);
    
    // Phase 1: Stat cards (INSTANT — uma query)
    const loadCounts = useCallback(async (forceRefresh = false) => {
        setCountsLoading(true);
        try {
            const resp = await fetchDashboardCounts(
                { expiring_days: dashboardSettings.expiring_days_ahead || 30 },
                forceRefresh,
            );
            if (resp?.data) {
                setDashCounts(resp.data);
            }
        } catch (err) {
            console.error("Dashboard counts error:", err);
        } finally {
            setCountsLoading(false);
        }
    }, [fetchDashboardCounts, dashboardSettings.expiring_days_ahead]);
    
    // Phase 2: Row data para tabs (DEFERRED — pode carregar enquanto usuário lê cards)
    const loadTabData = useCallback(async (forceRefresh = false) => {
        setDataLoading(true);
        try {
            const [clientsData, contractsData] = await Promise.all([
                fetchClients({}, forceRefresh),
                fetchContracts({}, forceRefresh),
            ]);
            setClients(clientsData.data || []);
            setContracts(contractsData.data || []);
        } catch (err) {
            console.error("Dashboard tab data error:", err);
        } finally {
            setDataLoading(false);
        }
    }, [fetchClients, fetchContracts]);
    
    // Dispara ambas ao carregar
    useEffect(() => {
        loadCounts(true);        // Instant (stat cards)
        loadTabData(true);       // Deferred (tabs)
    }, []);
    
    // Renderiza stat cards ANTES de tabData ficar pronto
    return (
        <div>
            <div className="dashboard-stats-grid">
                <div className="dashboard-stat-card">
                    <div className="dashboard-stat-label">Clientes Ativos</div>
                    <div className="dashboard-stat-value clients">
                        {countsLoading ? "…" : dashCounts?.clients?.active}
                    </div>
                </div>
                {/* mais cards usando dashCounts */}
            </div>
            
            {/* Tabs carregam enquanto usuário lê stats */}
            <div className="dashboard-info-tabs">
                {dataLoading ? (
                    <div>Carregando tabs...</div>
                ) : (
                    <>
                        {/* Birthday tab */}
                        {/* Expiring tab */}
                        {/* Expired tab */}
                    </>
                )}
            </div>
        </div>
    );
}
```

**Benefício**: Stat cards aparecem em ~100-200ms (uma query SQL rápida). Usuário vê números enquanto tabs carregam em background.

---

#### B) Página de Lista: Server-Side Pagination

```javascript
// ✅ NOVO: Clientes page com paginação server-side
export default function Clients() {
    const { fetchClients, fetchClientsCount } = useData();
    
    const [clients, setClients] = useState([]);
    const [totalItems, setTotalItems] = useState(0);
    const [counts, setCounts] = useState({ total: 0, active: 0, inactive: 0, archived: 0 });
    
    // URL state: filter, search, page, limit
    const { values, updateValue, updateValuesImmediate } = useUrlState({
        filter: "active",
        search: "",
        page: "1",
        limit: "20",
    });
    
    const filter = values.filter;
    const searchTerm = values.search;
    const currentPage = parseInt(values.page || "1", 10);
    const itemsPerPage = parseInt(values.limit || "20", 10);
    
    // Carrega counts (badges nos botões de filter)
    const loadCounts = useCallback(async (forceRefresh = false) => {
        try {
            const response = await fetchClientsCount({}, forceRefresh);
            if (response?.data) {
                setCounts(response.data);
            }
        } catch (err) {
            console.error("Error loading counts:", err);
        }
    }, [fetchClientsCount]);
    
    // Carrega dados paginados + filtrados + buscados
    const loadClients = useCallback(async (forceRefresh = false) => {
        try {
            const offset = (currentPage - 1) * itemsPerPage;
            const params = {
                include_stats: true,
                limit: itemsPerPage,
                offset,
            };
            
            // Adiciona filter (se não for "all")
            if (filter && filter !== "all") {
                params.filter = filter;
            }
            
            // Adiciona search (se não vazio)
            if (searchTerm) {
                params.search = searchTerm;
            }
            
            const response = await fetchClients(params, forceRefresh);
            setClients(response.data || []);
            setTotalItems(response.total ?? (response.data || []).length);
        } catch (err) {
            console.error("Error loading clients:", err);
        }
    }, [fetchClients, filter, searchTerm, currentPage, itemsPerPage]);
    
    // Initial load: counts + first page
    useEffect(() => {
        loadCounts(true);
    }, []);
    
    // Re-fetch quando filter/search/page mudam
    useEffect(() => {
        loadClients(true);
    }, [filter, searchTerm, currentPage, itemsPerPage]);
    
    return (
        <div className="clients-container">
            {/* Filter buttons com counts */}
            <div className="clients-filters">
                <button onClick={() => updateValuesImmediate({ filter: "all", page: "1" })}>
                    {g.all} ({counts.total})
                </button>
                <button onClick={() => updateValuesImmediate({ filter: "active", page: "1" })}>
                    {g.active} ({counts.active})
                </button>
                <button onClick={() => updateValuesImmediate({ filter: "inactive", page: "1" })}>
                    {g.inactive} ({counts.inactive})
                </button>
                <button onClick={() => updateValuesImmediate({ filter: "archived", page: "1" })}>
                    {g.archived} ({counts.archived})
                </button>
                
                {/* Search — debounced */}
                <input
                    type="text"
                    placeholder="Buscar..."
                    value={searchTerm}
                    onChange={(e) => updateValues({ search: e.target.value, page: "1" })}
                />
            </div>
            
            {/* Tabela: dados já vêm paginados/filtrados do servidor */}
            <ClientsTable filteredClients={clients} />
            
            {/* Paginação usa totalItems da resposta */}
            <Pagination
                currentPage={currentPage}
                totalItems={totalItems}
                itemsPerPage={itemsPerPage}
                onPageChange={(p) => updateValuesImmediate({ page: p.toString() })}
            />
        </div>
    );
}
```

**Antes vs Depois:**

| Aspecto | Antes | Depois |
|---------|-------|--------|
| Dados carregados | TODOS (10k+) | Apenas página (20) |
| Filtro | JavaScript (in-memory) | SQL WHERE |
| Busca | JavaScript (in-memory) | SQL LIKE |
| Paginação | Client-side slice | Server-side LIMIT/OFFSET |
| Requisições ao navegar (mesmo filter) | 1 (cache) | 1 (cache com params diferentes) |

---

#### C) API: Adicionar suporte a params nas chamadas

```javascript
// frontend/src/api/clientsApi.js
export const clientsApi = {
    getClients: async (apiUrl, token, params = {}, onTokenExpired) => {
        const queryParams = new URLSearchParams();
        
        // Pagination
        if (params.limit) queryParams.append("limit", params.limit);
        if (params.offset) queryParams.append("offset", params.offset);
        
        // Filters & Search
        if (params.filter) queryParams.append("filter", params.filter);
        if (params.search) queryParams.append("search", params.search);
        
        // Other
        if (params.include_stats) queryParams.append("include_stats", "true");
        if (params.include_archived) queryParams.append("include_archived", "true");
        
        const url = `${apiUrl}/clients${queryParams.toString() ? "?" + queryParams.toString() : ""}`;
        
        const response = await fetch(url, {
            headers: { Authorization: `Bearer ${token}` },
        });
        
        // Handle error...
        const data = await response.json();
        return data; // Retorna {data: [], total, limit, offset}
    },
};
```

#### D) DataContext: Adicionar métodos de counts

```javascript
// frontend/src/contexts/DataContext.jsx
export const DataProvider = ({ children, token, apiUrl, onTokenExpired }) => {
    const fetchDashboardCounts = useCallback(
        async (params = {}, forceRefresh = false) => {
            return fetchWithCache(
                "/dashboard/counts",
                { params },
                null,
                60 * 1000,  // 60s TTL para counts (mais curto que dados)
                forceRefresh,
            );
        },
        [fetchWithCache],
    );
    
    const fetchClientsCount = useCallback(
        async (params = {}, forceRefresh = false) => {
            return fetchWithCache(
                "/clients/counts",
                { params },
                null,
                60 * 1000,  // Counts TTL curto
                forceRefresh,
            );
        },
        [fetchWithCache],
    );
    
    // Retorna no value...
    const value = {
        // ... outros métodos
        fetchDashboardCounts,
        fetchClientsCount,
    };
    
    return (
        <DataContext.Provider value={value}>{children}</DataContext.Provider>
    );
};
```

---

## 📋 Checklist: Aplicar a Outras Entidades

Use este checklist ao implementar para **Contratos**, **Categorias**, **Afiliados**, etc:

### Backend

- [ ] **1. Criar tipo de Counts**
  ```go
  type [Entity]Counts struct {
      Total    int `json:"total"`
      Active   int `json:"active"`
      Archived int `json:"archived"`
      // ... outros campos específicos
  }
  ```

- [ ] **2. Implementar método Get[Entity]Counts() em Store**
  - Uma única query com CASE statements
  - Retorna agregações, não linhas

- [ ] **3. Implementar List[Entity]Paged() em Store**
  - Suporta `limit = 0` para "return all" (backward compatible)
  - `LIMIT $n OFFSET $m` quando limit > 0

- [ ] **4. Implementar Count[Entity]Filtered() em Store**
  - Mesmo WHERE que List, sem LIMIT/OFFSET
  - Reutiliza helper de WHERE building

- [ ] **5. Helper buildWhere[Entity]Clause()**
  - Evita duplicação entre List e Count
  - Retorna string com placeholders

- [ ] **6. Handler: handleList[Entity]()**
  ```go
  limit, offset := parseLimitOffset(r, 100, 500)
  filter := r.URL.Query().Get("filter")
  search := r.URL.Query().Get("search")
  
  data, err := s.store.List[Entity]FilteredPaged(filter, search, limit, offset)
  total, err := s.store.Count[Entity]Filtered(filter, search)
  
  respondJSON(w, http.StatusOK, map[string]interface{}{
      "data": data,
      "total": total,
      "limit": limit,
      "offset": offset,
  })
  ```

- [ ] **7. Handler: handleCount[Entity]()**
  ```go
  counts, err := s.store.Get[Entity]Counts()
  respondJSON(w, http.StatusOK, map[string]interface{}{
      "data": counts,
  })
  ```

- [ ] **8. Registrar rotas**
  ```go
  mux.HandleFunc("/api/[entities]/counts", 
      s.standardMiddleware(s.authMiddleware(s.handleCount[Entity])))
  
  mux.HandleFunc("/api/[entities]", 
      s.standardMiddleware(s.authMiddleware(s.handleList[Entity])))
  ```

### Frontend

- [ ] **1. Adicionar params ao API client**
  ```javascript
  if (params.limit) queryParams.append("limit", params.limit);
  if (params.offset) queryParams.append("offset", params.offset);
  if (params.filter) queryParams.append("filter", params.filter);
  if (params.search) queryParams.append("search", params.search);
  ```

- [ ] **2. Adicionar métodos ao DataContext**
  ```javascript
  const fetch[Entity]Count = useCallback(
      async (params = {}, forceRefresh = false) => {
          return fetchWithCache(
              "/[entities]/counts",
              { params },
              null,
              60 * 1000,
              forceRefresh,
          );
      },
      [fetchWithCache],
  );
  ```

- [ ] **3. Página de lista: Server-side pagination**
  - Parse filter, search, page, limit de URL state
  - Passa para API
  - Usa `total` da resposta para paginação
  - Re-fetch quando params mudam

- [ ] **4. Dashboard/Cards: Use counts endpoint**
  - Se tem cards de counts dessa entidade
  - Carrega counts em Phase 1
  - Row data (se necessário) em Phase 2

- [ ] **5. Cache invalidation**
  ```javascript
  // Após create/update/delete
  invalidateCache("[entity]");
  // Força re-fetch na próxima chamada
  ```

---

## 🧪 Validação: Como Testar

### Backend

```bash
# Test paged endpoint
curl -X GET "http://localhost:8080/api/clients?filter=active&limit=20&offset=0&search=joão"

# Resposta esperada:
{
  "data": [...20 clients...],
  "total": 150,
  "limit": 20,
  "offset": 0
}

# Test counts endpoint
curl -X GET "http://localhost:8080/api/clients/counts"

# Resposta esperada:
{
  "data": {
    "total": 1000,
    "active": 750,
    "inactive": 200,
    "archived": 50
  }
}

# Test dashboard counts
curl -X GET "http://localhost:8080/api/dashboard/counts?expiring_days=30"

# Resposta esperada:
{
  "data": {
    "clients": { "total": 1000, "active": 750, "inactive": 200, "archived": 50 },
    "contracts": { "total": 5000, "active": 3000, "expiring": 500, "expired": 1000, "archived": 500 },
    "categories": 25,
    "subcategories": 150
  }
}
```

### Frontend (Browser DevTools)

```javascript
// Abra Console
// 1. Verifique Network tab
// - Dashboard: deve fazer 2 requisições (counts + tab data)
// - Clients page: 1 req counts + 1 req list (não N+1)

// 2. Verifique Application > Local Storage
// - Cache deve ter keys diferentes por filter/page:
//   "/api/clients?filter=active&limit=20&offset=0"
//   "/api/clients?filter=inactive&limit=20&offset=0"
//   "/api/clients/counts"

// 3. Teste navegação
// - Mudar filter: deve fazer nova requisição (com novo limit/offset)
// - Volta atrás no browser: usa cache se dentro de TTL
// - Sair e voltar: forceRefresh=true ignora cache (primeiro load)
```

---

## 📊 Antes vs Depois: Impacto de Performance

### Dashboard (5k clientes, 10k contratos, 20 categorias × 3 subcategorias)

| Métrica | Antes | Depois | Melhoria |
|---------|-------|--------|----------|
| **Requisições** | 24 (4 + 20 subcategorias) | 2 (1 counts + 1 tab data) | **92% menos** |
| **Dados JSON** | ~500KB | ~50KB (counts) + ~100KB (tab) = 150KB | **70% menos** |
| **Tempo até Stat Cards** | 8-15s (bloqueado) | ~100-200ms | **50-100x mais rápido** |
| **Tempo até Tabs** | 8-15s (já tem dados) | ~1-2s (em paralelo) | **4-8x mais rápido** |
| **Requisições/hora em prod** | 288 (24 × 12) | 24 (2 × 12) | **92% menos carga** |

### Clients Page (5k clientes, página 1 com 20 itens)

| Métrica | Antes | Depois | Melhoria |
|---------|-------|--------|----------|
| **Dados JSON** | ~500KB (tudo) | ~20KB (20 items) | **96% menos** |
| **Filtro no FE** | ~100-200ms (JS) | ~20ms (servidor) | **5-10x mais rápido** |
| **Paginação** | ~10ms (slice) | ~5ms (URL update) | Similar |
| **Navegação filter+page** | 1 req (cache) + JS filter | 1 req (novo params) | Similar, mas escalável |

---

## ⚠️ Armadilhas Comuns

### 1. Esquecer de retornar `{data, total, limit, offset}`

```go
// ❌ ERRADO: responde só com array
respondJSON(w, http.StatusOK, clients)

// ✅ CORRETO: metadados de paginação
respondJSON(w, http.StatusOK, map[string]interface{}{
    "data": clients,
    "total": total,
    "limit": limit,
    "offset": offset,
})
```

### 2. Não suportar `limit=0` para backward compatibility

```go
// ❌ PROBLEMA: retorna erro se limit=0
if limit == 0 {
    return nil, errors.New("limit must be > 0")
}

// ✅ CORRETO: limit=0 significa "return all"
if limit <= 0 {
    // Sem LIMIT/OFFSET na query
} else {
    // Com LIMIT/OFFSET
}
```

### 3. Duplicar WHERE clause entre List e Count

```go
// ❌ ERRADO: copiar/colar WHERE em duas funções
func (s *Store) List...() {
    query := "WHERE archived_at IS NULL AND status='ativo'"
}
func (s *Store) Count...() {
    query := "WHERE archived_at IS NULL AND status='ativo'"  // Duplicado!
}

// ✅ CORRETO: helper compartilhado
func buildWhere(...) string {
    return "WHERE archived_at IS NULL AND status='ativo'"
}
func (s *Store) List...() {
    query := "FROM entity" + buildWhere()
}
func (s *Store) Count...() {
    query := "SELECT COUNT(*) FROM entity" + buildWhere()
}
```

### 4. Não invalidar cache após mutations

```go
// ❌ ERRADO: cria cliente mas cache fica stale
await createClient(data);
// Usuário vê lista antiga

// ✅ CORRETO: invalida cache + re-fetch
await createClient(data);
invalidateCache("clients");  // Limpa counts + lista
await loadCounts(true);      // Força re-fetch (ignora cache)
await loadClients(true);
```

### 5. Enviar `limit` sempre (mesmo quando não quer paginar)

```javascript
// ❌ ERRADO: Dashboard carrega tudo paginado
const response = await fetchClients({ limit: 20, offset: 0 });
// Vai buscar só os primeiros 20, perde dados das tabs

// ✅ CORRETO: Dashboard sem limit (full load), Clients page com limit
// Dashboard:
const response = await fetchClients({});  // Sem limit = tudo
// Clients page:
const response = await fetchClients({ limit: 20, offset: 0 });
```

---

## 🔗 Referências Rápidas

### Padrão de Resposta API
```json
{
  "data": [/* array de entities */],
  "total": 1000,
  "limit": 20,
  "offset": 0
}
```

### Padrão de Counts API
```json
{
  "data": {
    "total": 1000,
    "active": 750,
    "inactive": 200,
    "archived": 50
  }
}
```

### URL Query Params Suportados
```
GET /api/[entities]
  ?filter=active|inactive|archived|all   (opcional)
  &search=term                            (opcional, para nome/email)
  &limit=20                               (opcional, max 500)
  &offset=0                               (opcional)
  &include_archived=true                  (opcional, default false para list)
  &include_stats=true                     (opcional, contrato stats)
```

### Rotas Criadas

| Rota | Método | Descrição | TTL Cache |
|------|--------|-----------|-----------|
| `/api/dashboard/counts` | GET | Todos os counts para dashboard | 60s |
| `/api/clients/counts` | GET | Client counts para badges | 60s |
| `/api/contracts/counts` | GET | Contract counts | 60s |
| `/api/clients` | GET | Lista paginada/filtrada | 5m |
| `/api/contracts` | GET | Lista paginada | 5m |
| `/api/categories` | GET | Lista paginada | 5m |

---

## 📝 Resumo Executivo

**Problema**: Aplicação carregava dados desnecessários, causando lentidão.

**Solução**: 
1. **Tier 1 (Counts)**: Endpoints leves retornam só agregações (1 query)
2. **Tier 2 (Paging)**: APIs retornam dados paginados/filtrados (servidor)
3. **Tier 3 (Detail)**: Endpoints de detalhes individuais (já existentes)

**Resultado**:
- Dashboard: 24 req → 2 req (92% menos)
- Dashboard speed: 8-15s → 100ms cards + 1-2s tabs
- Clients page: 5k items → 20 items por página
- Banco de dados: carga reduzida em ~90%

**Próximos passos**: Aplicar padrão a **Contratos, Categorias, Afiliados, Usuários**.

---

**Documento criado em**: Janeiro 2025  
**Implementado em**: Clientes e Dashboard  
**Status**: Pronto para replicação
---

## 🔧 Fase 2: Bugs Encontrados e Correções (Atualização)

### 🐛 Bugs Identificados na Página de Clientes

#### 1. Contagens exibindo "0" nos filtros
**Causa raiz**: Rota `/api/clients/counts` registrada DEPOIS do handler subtree `/api/clients/`, criando potencial conflito de roteamento no Go ServeMux.

**Correção**:
- Movida a rota `/api/clients/counts` para ANTES do handler subtree
- Adicionado guard explícito no handler subtree para redirecionar `/counts` ao handler correto
- Adicionado fallback no frontend: se o endpoint de counts falhar, calcula counts a partir de fetch sem filtro

#### 2. Filtro e busca não funcionando
**Causa raiz**: Frontend usava `useCallback` sem dependências corretas, causando stale closures. Busca server-side não incluía nomes de afiliados.

**Correção**:
- `loadClients` e `loadCounts` agora usam `useCallback` com deps corretas `[fetchClients, filter, searchTerm, currentPage, itemsPerPage]`
- `useEffect` depende de `[loadClients]` em vez de deps manuais com eslint-disable
- Busca no backend (`buildClientFilterWhere`) agora inclui subquery em affiliates: `OR EXISTS (SELECT 1 FROM affiliates WHERE affiliates.client_id = clients.id AND LOWER(affiliates.name) LIKE $N)`
- Adicionado `console.debug` para rastreamento de params enviados

### ✅ Otimizações Aplicadas a Outras Entidades

#### Contratos (`/api/contracts`)
- **Backend**: `buildContractFilterWhere` com filtros `active`, `expired`, `expiring`, `not_started`, `archived`
- **Backend**: `ListContractsFilteredPaged` e `CountContractsFiltered` com suporte a busca por model, item_key e nome do cliente (via subquery)
- **Backend**: Novo endpoint `GET /api/contracts/counts` com `handleContractCounts` retornando `{ total, active, expiring, expired, archived }`
- **Rota**: Registrada antes do handler subtree com guard explícito
- **Frontend**: `fetchContractsCount` adicionado ao DataContext

#### Categorias (`/api/categories`)
- **Backend**: Já tinha `ListCategoriesPaged`, `CountCategories`, resposta `{data, total, limit, offset}` ✅
- **Dashboard**: Counts via `/api/dashboard/counts` em paralelo ✅

#### Usuários (`/api/users`)
- **Backend**: `handleListUsers` agora retorna `{data, total, limit, offset}` ao invés de `SuccessResponse{Data: ...}`
- Suporte a paginação via `parseLimitOffset`

#### Financeiro (`/api/financial`)
- **Backend**: `handleListFinancial` agora retorna `{data, total, limit, offset}` ao invés de `SuccessResponse{Data: ...}`

#### Audit Logs (`/api/audit-logs`)
- Já tinha paginação + filtros avançados + `{data, total, limit, offset}` ✅

### 📊 Rotas de Counts Registradas

| Rota | Handler | Descrição |
|------|---------|-----------|
| `GET /api/dashboard/counts` | `handleDashboardCounts` | Counts agregados para stat cards do dashboard |
| `GET /api/clients/counts` | `handleClientCounts` | `{ total, active, inactive, archived }` |
| `GET /api/contracts/counts` | `handleContractCounts` | `{ total, active, expiring, expired, archived }` |

### 🛡️ Padrão de Segurança de Rotas

Para evitar conflitos do Go ServeMux entre rotas subtree (`/api/entity/`) e rotas exatas (`/api/entity/counts`):

```
// 1. Registrar rota exata ANTES do subtree
mux.HandleFunc("/api/entity/counts", handler)
mux.HandleFunc("/api/entity/", subtreeHandler)

// 2. Adicionar guard no subtree handler
if r.URL.Path == "/api/entity/counts" {
    countsHandler(w, r)
    return
}
```

---

## 🔧 Fase 3: Cache-First, Idempotência e Loading States (Atualização)

### 🐛 Problemas Identificados

#### 1. Filtro de Clientes causava refresh na página inteira
**Causa raiz**: O padrão `if (loading) { return <loading screen> }` substituía o componente INTEIRO (incluindo o campo de busca) quando `setLoading(true)` era chamado. Ao digitar na busca → `loadClients` mudava deps → useEffect disparava → `setLoading(true)` → página inteira desmontada → input de busca perdido → usuário via "refresh".

**Correção**:
- Separado `loading` (full-page, só no primeiro load) de `tableLoading` (overlay só na tabela)
- `initialLoadDone` ref controla qual loading mostrar
- Primeiro mount: tela de carregamento completa
- Loads subsequentes (busca, filtro, paginação): overlay transparente apenas sobre a tabela, filtros/busca permanecem interativos

#### 2. Página de Categorias extremamente lenta — ⚠️ PROBLEMA AINDA EXISTE

**Status**: Backend está OK, MAS frontend compensa com N+1 de HTTP calls

**Causa raiz real**:
- ✅ Backend (`handleListCategories`) é EFICIENTE: retorna categorias + subcategorias em 3 queries
- ❌ Frontend IGNORA o field `lines` que já vem no response e re-busca subcategorias
- ❌ `loadAllLinesInBackground()` dispara 2010 HTTP requests paralelos (com 2010 categorias)

**Correção INCOMPLETA**:
- ✅ Migrado para `DataContext.fetchCategories` com cache
- ✅ Subcategorias carregam em background não-bloqueante
- ❌ MAS: continua re-buscando via `fetchSubcategories()` ao invés de usar field `lines` existente
- ❌ Resultado: 2010 categorias = 2010 API calls na primeira carga (mesmo com cache)

**Solução Correta** (ver PERFORMANCE_DIAGNOSIS.md Fase 2):
- Remover `loadAllLinesInBackground()` completamente
- Usar field `lines` que já vem do response do backend
- Resultado: 2010 API calls → 0 (dados já vêm no response)

#### 3. Todas as páginas carregavam do zero ao navegar
**Causa raiz**: Toda página fazia `loadData(true)` (forceRefresh=true) no mount, ignorando completamente o cache do `DataContext`. Quando o usuário navegava entre páginas, componentes desmontavam/remontavam e começavam com estado vazio + loading.

**Correção**:
- **Cache-first**: Initial loads agora usam `forceRefresh=false` — se há dados em cache, aparecem instantaneamente
- **Force refresh apenas em mutations**: `reloadAfterMutation()` invalida cache e força refresh
- Cada combinação de params (filter/search/page) tem uma cache key única no `cacheManager`, então filtros diferentes não servem dados stale

### ✅ Páginas Corrigidas — COM RESSALVAS

| Página | Loading State | Cache-First | Filtragem | Status |
|--------|--------------|-------------|-----------|--------|
| **Clients** | ✅ `initialLoadDone` guard | ✅ `loadClients(false)` | ✅ Server-side | ✅ OK |
| **Categories** | ✅ `initialLoadDone` guard | ✅ `fetchCategories(false)` | N/A | ⚠️ Frontend re-fetch ainda existe |
| **Contracts** | ✅ `initialLoadDone` guard | ✅ `loadInitialData(false)` | ✅ Server-side | ✅ OK |
| **Users** | ✅ `initialLoadDone` guard | ⬜ API direta, sem DataContext | ❌ Client-side | ⚠️ Sem cache |
| **Financial** | ✅ `initialLoadDone` guard | ✅ `loadData(false)` | ❌ Client-side | 🔴 CRÍTICO: Query bomb não corrigida |
| **Dashboard** | ✅ Two-phase | ✅ `loadCounts(false)` | N/A | ✅ OK |

### 📊 Padrão Implementado

```javascript
// ── Estado ──
const [loading, setLoading] = useState(false);        // Full-page (só primeiro load)
const [tableLoading, setTableLoading] = useState(true); // Overlay na tabela
const initialLoadDone = useRef(false);

// ── Load function ──
const loadData = useCallback(async (forceRefresh = false) => {
    if (!initialLoadDone.current) setLoading(true);  // Full-page só no primeiro
    setTableLoading(true);                            // Overlay sempre
    try {
        const response = await fetchData(params, forceRefresh);
        setData(response.data || []);
    } finally {
        setLoading(false);
        setTableLoading(false);
        initialLoadDone.current = true;
    }
}, [fetchData, params]);

// ── Mount: cache-first ──
useEffect(() => { loadData(false); }, [loadData]);

// ── Mutations: force refresh ──
const reloadAfterMutation = async () => {
    invalidateCache("resource");
    await loadData(true);
};

// ── Render: guard condicional ──
if (loading && !initialLoadDone.current) {
    return <FullPageLoading />;
}
return (
    <div style={{ position: "relative" }}>
        {tableLoading && initialLoadDone.current && <TableOverlay />}
        <DataTable data={data} />
    </div>
);
```

### 🧠 ⚠️ Otimização Extra: Categories — Ainda Problemática

**Status**: Melhorou (não bloqueia mais), MAS continua re-buscando

```javascript
// ANTES: Bloqueante + N+1 queries
const loadCategories = async () => {
    setLoading(true);  // ← congelava página
    const data = await fetchCategories();
    // N requests sequenciais (bloqueante)
    const allLines = await Promise.all(data.map(cat => fetchSubcategories(cat.id)));
    setLoading(false);
};

// AGORA: Não-bloqueante MAS continua N+1 de HTTP calls
const loadCategories = async (forceRefresh) => {
    if (!initialLoadDone.current) setLoading(true);
    setTableLoading(true);
    const data = await fetchCategories(forceRefresh);  // 1 request
    setCategories(data);
    setLoading(false);
    setTableLoading(false);
    // ❌ Depois faz 2010 HTTP calls paralelos (melhor que sequencial, mas ainda problemático)
    loadAllLinesInBackground(data, forceRefresh);      // async, non-blocking
};

// ✅ SOLUÇÃO CORRETA (Fase 2 do PERFORMANCE_DIAGNOSIS.md):
// - REMOVER loadAllLinesInBackground()
// - O backend JÁ retorna field 'lines' com subcategorias
// - Apenas fazer: const allLines = data.flatMap(cat => cat.lines || []);
```

### 📊 Antes vs Depois — COM REALIDADE

| Cenário | Antes | Implementado | Ainda Falta |
|---------|-------|--------------|-------------|
| Clients: digitar na busca | Página inteira refresh | Overlay apenas tabela ✅ | N/A |
| Categories: primeiro load (2010 cats) | N/A (não existia) | 1 request + 2010 em background ❌ | Remover re-fetch, usar `lines` field ⚠️ |
| Categories: re-visita | N/A | 0 requests (cache) ✅ | Aplicar após remover re-fetch |
| Financial: primeiro load | N/A | ~25s (query bomb) 🔴 | Refatorar getPeriodSummary (P0) |
| Financial: re-visita | N/A | ~25s (sem cache) 🔴 | Sem cache na API |
| Mutation | Reload do zero | `invalidateCache()` + refresh ✅ | N/A |

### ⚠️ Notas Importantes

1. **Cache TTL**: Dados gerais = 5min, Counts = 1min (via DataContext)
2. **Cache keys são param-aware**: `fetchClients({filter:"active",page:1})` e `fetchClients({filter:"inactive",page:1})` são entradas de cache diferentes
3. **Mutations sempre invalidam**: `reloadAfterMutation()` chama `invalidateCache("resource")` antes de `forceRefresh=true`
4. **Background loading não bloqueia UI**: Se subcategorias ainda estão carregando, a busca por nome de subcategoria simplesmente não encontra resultados até terminar

---

## 🔴 Problemas NÃO Endereçados (Críticos)

### Financial — Query Bomb em `GetFinancialDetailedSummary`

**Problema**: Endpoint dispara ~15.000-20.000 queries SQL por request

```
GET /api/financial/summary/detailed
  ↓
GetFinancialDetailedSummary() [L767-823]
  ├─ 1 query (totais gerais) ✅
  └─ Loop 10x: getPeriodSummary()
       └─ getPeriodSummary() [L826-1028] — N+1 AQUI!
           ├─ 1 query (installments período) ✅
           ├─ 1 query (TODOS 1985 recorrentes) ⚠️
           └─ Loop ~1500x: verificação individual de installment status
               └─ 1500 queries × 10 períodos = 15.000 QUERIES
```

**Impacto**: Financial página congela por 15-20s, PostgreSQL fica saturado

**Solução**: Ver PERFORMANCE_DIAGNOSIS.md, Fase 1 (P0) — 2-3 dias

### Financial — Sem Paginação + N+1 Futuro

**Problema**: `GetAllFinancials()` carrega 4387 registros sem paginar

**Solução**: Ver PERFORMANCE_DIAGNOSIS.md, Fase 1.3 — implementar paginação real

### Categories — Frontend re-busca 2010 vezes

**Problema**: `loadAllLinesInBackground()` ignora field `lines` que já vem do backend

**Solução**: Ver PERFORMANCE_DIAGNOSIS.md, Fase 2 (P1) — 1 dia

### Financial — Filtragem Client-side

**Problema**: 4387 registros carregados, 15+ filtros em JavaScript bloqueiam UI

**Solução**: Ver PERFORMANCE_DIAGNOSIS.md, Fase 3.2 (P2) — server-side filtering

---

**Implementado**: Fase 3 — Janeiro 2025  
**Status**: ⚠️ **Parcial** — Clients e Dashboard OK, mas Financial e Categories ainda críticos  
**Próximo**: Consultar PERFORMANCE_DIAGNOSIS.md para roadmap P0/P1/P2
