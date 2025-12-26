# Rate Limiting - Entity Hub

## Visão Geral

O Entity Hub implementa rate limiting no backend para proteger contra abuso e ataques de força bruta. O sistema limita o número de requisições por IP em um período de tempo específico.

## Configuração

### Variáveis de Ambiente

O rate limiting é configurado através das seguintes variáveis de ambiente:

| Variável | Descrição | Padrão | Recomendado (Dev) | Recomendado (Prod) |
|----------|-----------|--------|-------------------|-------------------|
| `RATE_LIMIT` | Requisições por segundo por IP | 5 | 100 | 10-20 |
| `RATE_BURST` | Máximo de requisições em burst | 10 | 200 | 20-50 |

### Configuração para Desenvolvimento

Durante o desenvolvimento, especialmente com React StrictMode habilitado, você pode aumentar os limites:

```bash
# No seu shell ou arquivo .env
export RATE_LIMIT=100
export RATE_BURST=200
```

Ou ao iniciar o servidor:

```bash
RATE_LIMIT=100 RATE_BURST=200 ./ehop-backend-dev
```

### Configuração para Produção

Em produção, mantenha valores conservadores para segurança:

```bash
export RATE_LIMIT=20
export RATE_BURST=50
```

## Como Funciona

### Token Bucket Algorithm

O sistema usa o algoritmo Token Bucket:

1. **Rate Limit**: Taxa de reposição de tokens (requisições/segundo)
2. **Burst**: Capacidade máxima do bucket (requisições simultâneas)

#### Exemplo Prático

Com `RATE_LIMIT=5` e `RATE_BURST=10`:

- Você pode fazer até 10 requisições imediatamente (burst)
- Depois disso, pode fazer 5 requisições por segundo
- Se esperar 10 segundos, o bucket recarrega completamente

### Rate Limiting por IP

O sistema rastreia cada IP separadamente:

```go
// Cada IP tem seu próprio limiter
limiter := rateLimiter.GetLimiter(clientIP)

if !limiter.Allow() {
    // Retorna 429 Too Many Requests
    return
}
```

### Limpeza Automática

Para evitar vazamento de memória, o sistema limpa IPs inativos:

- Executa a cada 10 minutos
- Remove limiters não utilizados
- Reinicia o mapa se ultrapassar 10.000 IPs

## Resposta 429 (Too Many Requests)

Quando o rate limit é excedido, o servidor retorna:

```json
{
    "error": "Rate limit exceeded"
}
```

Status HTTP: `429 Too Many Requests`

## Integração com o Sistema de Cache

O frontend implementa um sistema de cache robusto que trabalha em conjunto com o rate limiting:

### Como o Cache Ajuda

1. **Reduz requisições**: Dados são servidos do cache por até 5 minutos
2. **Deduplicação**: Evita requisições simultâneas duplicadas
3. **Refresh controlado**: Usuário decide quando buscar dados frescos

### Exemplo de Uso

```javascript
import { useData } from '../contexts/DataContext';

function MyComponent() {
    const { fetchEntities } = useData();
    
    // Primeira chamada: vai ao servidor
    const data1 = await fetchEntities();
    
    // Segunda chamada (dentro de 5 min): retorna do cache
    const data2 = await fetchEntities(); // Não faz requisição!
    
    // Força refresh (ignora cache)
    const freshData = await fetchEntities({}, true);
}
```

Veja [CACHE_SYSTEM.md](./CACHE_SYSTEM.md) para mais detalhes.

## Troubleshooting

### Problema: Muitos 429 Errors em Desenvolvimento

**Sintomas**:
- Console mostrando múltiplos `429 Too Many Requests`
- Dados não carregam
- React StrictMode causa requisições duplicadas

**Soluções**:

1. **Aumentar Rate Limit (Recomendado para Dev)**:
   ```bash
   export RATE_LIMIT=100
   export RATE_BURST=200
   ```

2. **Usar o Sistema de Cache**:
   - Certifique-se de usar `useData()` hook
   - Não force refresh desnecessariamente
   - Deixe o cache trabalhar

3. **Desabilitar React StrictMode temporariamente**:
   ```javascript
   // main.jsx
   root.render(
       // <React.StrictMode>  // Comentar em dev
           <App />
       // </React.StrictMode>
   );
   ```

### Problema: 429 em Produção

**Soluções**:

1. **Ajustar limites do servidor**:
   - Aumente `RATE_LIMIT` para usuários legítimos
   - Mantenha valores razoáveis (20-50)

2. **Verificar se há muitas requisições**:
   - Use ferramentas de monitoramento
   - Verifique logs do servidor
   - Identifique endpoints problemáticos

3. **Implementar caching mais agressivo**:
   - Aumente TTL do cache no frontend
   - Implemente CDN para assets estáticos
   - Use cache HTTP no servidor

### Problema: Performance Lenta

**Possíveis causas relacionadas ao rate limiting**:

1. **Muitos IPs no limiter**:
   - Limpeza automática deve resolver
   - Monitore uso de memória

2. **Requisições sendo bloqueadas**:
   - Verifique logs para 429 errors
   - Ajuste limites se necessário

## Monitoramento

### Logs do Servidor

O servidor registra quando rate limiting é aplicado:

```
Rate limit exceeded for IP: 192.168.1.100
```

### Métricas Recomendadas

Monitore as seguintes métricas:

- **429 Errors/min**: Taxa de rate limiting
- **Requisições/IP**: Distribuição de requisições
- **Latência**: Impacto do rate limiting na performance

### Exemplo de Log Analysis

```bash
# Contar 429 errors nos últimos 5 minutos
grep "429" logs/server.log | grep "$(date +%Y-%m-%d)" | tail -100

# IPs com mais rate limiting
grep "Rate limit exceeded" logs/server.log | awk '{print $NF}' | sort | uniq -c | sort -rn
```

## Endpoints Protegidos

Todos os endpoints da API são protegidos por rate limiting:

- ✅ `/api/login`
- ✅ `/api/agreements`
- ✅ `/api/entities`
- ✅ `/api/categories`
- ✅ `/api/users`
- ✅ `/api/audit-logs`
- ✅ Todos os outros endpoints

### Endpoints de Inicialização

Os endpoints de inicialização têm proteção especial:

- `/api/initialize/*`: Rate limiting mais agressivo
- Proteção contra abuso durante setup inicial

## Boas Práticas

### Para Desenvolvedores

1. **Use valores altos em desenvolvimento**:
   ```bash
   RATE_LIMIT=100 RATE_BURST=200
   ```

2. **Use o sistema de cache**:
   - Sempre use `useData()` hook
   - Não faça `fetch()` direto

3. **Teste com valores de produção antes do deploy**:
   ```bash
   RATE_LIMIT=20 RATE_BURST=50
   ```

### Para Produção

1. **Configure valores apropriados**:
   - Considere seu tráfego esperado
   - Ajuste baseado em métricas reais

2. **Monitore constantemente**:
   - Configure alertas para 429 errors
   - Revise logs regularmente

3. **Documente mudanças**:
   - Registre ajustes de rate limiting
   - Documente razões para mudanças

### Para Usuários/Admins

1. **Use o botão "Atualizar"**:
   - Não recarregue a página constantemente
   - Use o botão 🔄 quando necessário

2. **Aguarde entre operações**:
   - O sistema tem cache de 5 minutos
   - Não force refresh repetidamente

## Configuração por Ambiente

### Docker Compose

```yaml
services:
  backend:
    environment:
      - RATE_LIMIT=20
      - RATE_BURST=50
```

### Kubernetes

```yaml
env:
  - name: RATE_LIMIT
    value: "20"
  - name: RATE_BURST
    value: "50"
```

### Systemd Service

```ini
[Service]
Environment="RATE_LIMIT=20"
Environment="RATE_BURST=50"
```

## Segurança

### Proteção contra DDoS

O rate limiting ajuda a proteger contra:

- **Flood attacks**: Múltiplas requisições rápidas
- **Brute force**: Tentativas de login repetidas
- **Scraping**: Extração massiva de dados

### Limitações

O rate limiting **não protege** completamente contra:

- **DDoS distribuído**: Múltiplos IPs diferentes
- **Slow attacks**: Requisições lentas e espaçadas
- **Layer 7 attacks**: Ataques específicos da aplicação

Para proteção completa, considere:

- WAF (Web Application Firewall)
- Cloudflare ou similar
- Rate limiting em múltiplas camadas

## FAQ

### Q: Por que o padrão é tão baixo (5 req/s)?

**A**: Para garantir segurança out-of-the-box. O sistema de cache do frontend compensa completamente essa limitação.

### Q: Posso desabilitar o rate limiting?

**A**: Não é recomendado, mas você pode definir valores muito altos:
```bash
RATE_LIMIT=10000 RATE_BURST=20000
```

### Q: O rate limiting afeta performance?

**A**: Minimamente. O overhead é de alguns microsegundos por requisição.

### Q: Como funciona com proxy reverso?

**A**: O sistema detecta o IP real através dos headers:
- `X-Real-IP`
- `X-Forwarded-For`
- IP direto da conexão

### Q: Rate limiting é por usuário ou por IP?

**A**: Por IP. Múltiplos usuários no mesmo IP compartilham o limite.

## Recursos Adicionais

- [CACHE_SYSTEM.md](./CACHE_SYSTEM.md) - Sistema de cache do frontend
- [Backend Config](../backend/config/config.go) - Código de configuração
- [Middleware Security](../backend/server/middleware_security.go) - Implementação do rate limiting

## Conclusão

O rate limiting do Entity Hub foi projetado para:

- ✅ Proteger contra abuso
- ✅ Ser flexível e configurável
- ✅ Trabalhar perfeitamente com o cache do frontend
- ✅ Ter impacto mínimo na performance

Configure adequadamente para seu ambiente e deixe o sistema trabalhar por você!