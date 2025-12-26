# Cálculo de Entropia de Senha

## O que é Entropia?

Entropia é uma medida da aleatoriedade/força de uma senha. Representa quantos bits de informação aleatória uma senha contém. Quanto maior a entropia, mais difícil é quebrar a senha por força bruta.

**Fórmula:**
```
Entropia (bits) = min_length × log₂(charset_size)
```

## Cálculo do Tamanho do Conjunto de Caracteres (charset_size)

O conjunto de caracteres disponíveis é calculado com base nos requisitos da política:

| Tipo | Quantidade | Exemplos |
|------|-----------|----------|
| **Minúsculas** | 26 | a-z |
| **Maiúsculas** | 26 | A-Z |
| **Dígitos** | 10 | 0-9 |
| **Especiais** | 32 | !@#$%^&*()_+-=[]{}... |

**Se nenhum tipo for exigido:** assume-se 94 caracteres (todos os tipos)

### Exemplos de Cálculo

#### Exemplo 1: Política do Role ROOT
```
Requisitos: 24 caracteres, maiúsculas, minúsculas, números, especiais
charset_size = 26 + 26 + 10 + 32 = 94
entropia = 24 × log₂(94) = 24 × 6.55 ≈ 157 bits
Nível: Muito Forte ✓
```

#### Exemplo 2: Política do Role ADMIN
```
Requisitos: 16 caracteres, maiúsculas, minúsculas, números, especiais
charset_size = 26 + 26 + 10 + 32 = 94
entropia = 16 × log₂(94) = 16 × 6.55 ≈ 105 bits
Nível: Forte ✓
```

#### Exemplo 3: Política do Role USER
```
Requisitos: 12 caracteres, maiúsculas, minúsculas, números (sem especiais)
charset_size = 26 + 26 + 10 = 62
entropia = 12 × log₂(62) = 12 × 5.95 ≈ 71 bits
Nível: Média ✓
```

#### Exemplo 4: Política do Role VIEWER
```
Requisitos: 8 caracteres, maiúsculas, minúsculas (sem números, sem especiais)
charset_size = 26 + 26 = 52
entropia = 8 × log₂(52) = 8 × 5.70 ≈ 46 bits
Nível: Básica ⚠️
```

#### Exemplo 5: Política Global (Padrão)
```
Requisitos: 8 caracteres, maiúsculas, minúsculas, números, especiais
charset_size = 26 + 26 + 10 + 32 = 94
entropia = 8 × log₂(94) = 8 × 6.55 ≈ 52 bits
Nível: Básica ⚠️
```

## Classificação de Força por Entropia

| Faixa | Nível | Segurança | Exemplo |
|-------|-------|-----------|---------|
| < 50 bits | Fraca | ❌ Muito vulnerável | 7 caracteres aleatórios |
| 50-90 bits | Básica | ⚠️ Aceitável | 8-12 caracteres com 4 tipos |
| 90-120 bits | Média | ✓ Boa | 14-16 caracteres com 3-4 tipos |
| 120-160 bits | Forte | ✓✓ Muito boa | 18-24 caracteres com todos os tipos |
| > 160 bits | Muito Forte | ✓✓✓ Excelente | 24+ caracteres com todos os tipos |

## Implementação no Sistema

### Frontend (React)

O cálculo é feito em tempo real no componente `RolePasswordPolicies.jsx`:

```javascript
const calculatePasswordScore = (policy) => {
    let charsetSize = 0;
    if (policy.require_lowercase) charsetSize += 26;
    if (policy.require_uppercase) charsetSize += 26;
    if (policy.require_numbers) charsetSize += 10;
    if (policy.require_special) charsetSize += 32;
    
    if (charsetSize === 0) charsetSize = 94;
    
    const entropy = policy.min_length * Math.log2(charsetSize);
    return Math.round(entropy);
};
```

**Quando é calculada:**
- Ao exibir a lista de políticas
- Ao editar uma política (preview em tempo real)
- Para mostrar a força estimada da política

### Backend (Go)

**Atual:** O backend não valida entropia (apenas validações de range simples)

**Potencial futura implementação:**
```go
func CalculateEntropy(minLength int, requireLower, requireUpper, requireNumbers, requireSpecial bool) float64 {
    charsetSize := 0
    if requireLower { charsetSize += 26 }
    if requireUpper { charsetSize += 26 }
    if requireNumbers { charsetSize += 10 }
    if requireSpecial { charsetSize += 32 }
    
    if charsetSize == 0 { charsetSize = 94 }
    
    return float64(minLength) * math.Log2(float64(charsetSize))
}
```

## Por que a Entropia não é Validada no Backend?

1. **É uma métrica informativa, não um limite**: A entropia ajuda a entender a força, mas não é um requisito obrigatório
2. **Múltiplas combinações são válidas**: 8 chars com 4 tipos (52 bits) = 16 chars com 2 tipos (52 bits)
3. **Simplicidade**: Validar ranges individuais (min_length 8-128, etc) é mais direto e fácil de entender

## Configurações Globais

As definições padrão no banco de dados:

```sql
security.password_min_length = '8'           -- Range: 8-128 caracteres
security.password_max_length = '128'         -- Range: 8-256 caracteres
security.password_require_uppercase = 'true'
security.password_require_lowercase = 'true'
security.password_require_numbers = 'true'
security.password_require_special = 'true'
security.password_entropy_min_bits = '90'    -- Apenas informativo para UI
```

**Entropia resultante da política global:**
```
8 × log₂(94) ≈ 52 bits (Básica)
```

## Recomendações de Segurança

| Tipo de Usuário | Min Entropia | Exemplo de Política | Rationale |
|-----------------|--------------|-------------------|-----------|
| **Viewer** (leitura) | 40-60 bits | 8 chars + 2-3 tipos | Acesso limitado |
| **User** (operacional) | 70-100 bits | 12-14 chars + 3 tipos | Dados normais |
| **Admin** (gerencial) | 100-130 bits | 16-18 chars + 4 tipos | Dados sensíveis |
| **Root** (crítico) | 150+ bits | 24+ chars + 4 tipos | Máxima segurança |

## Referências

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html): Password Guidelines
- [EFF Diceware](https://www.eff.org/dice): Entropy and passphrase strength
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)): Information Theory
