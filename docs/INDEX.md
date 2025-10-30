# 📚 Documentação — Licenses Manager

Bem-vindo! Esta página ajuda você a encontrar o que precisa.

## 🎯 Comece Aqui

**Primeira vez?**
- Leia [README.md](../README.md) — Visão geral e quick start (3 min)
- Siga [SETUP.md](SETUP.md) — Instale e configure (10 min)
- Teste em [USAGE.md](USAGE.md) — Exemplos práticos (5 min)

**Pronto em 20 minutos!**

---

## 📖 Documentação Completa

| Documento | Para quem | Tempo | O que contém |
|-----------|-----------|-------|-------------|
| **[README.md](../README.md)** | Todos | 3 min | Visão geral, quick start, estrutura |
| **[SETUP.md](SETUP.md)** | Devs/Ops | 10 min | Instalação, configuração, troubleshooting |
| **[USAGE.md](USAGE.md)** | Usuários | 15 min | Comandos, casos de uso, FAQ |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Devs | 20 min | Design técnico, padrões, fluxos |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Contribuidores | 15 min | Desenvolvimento, testes, PRs |
| **[CHANGELOG.md](../CHANGELOG.md)** | Todos | 2 min | Histórico de versões |

---

## 🔍 Procurando por...

### Instalação?
→ [SETUP.md](SETUP.md) — Passo a passo completo

### Como usar o sistema?
→ [USAGE.md](USAGE.md) — Comandos e exemplos

### Erro ou problema?
→ [SETUP.md — Troubleshooting](SETUP.md#-troubleshooting) — Soluções comuns

### Como contribuir?
→ [CONTRIBUTING.md](CONTRIBUTING.md) — Guia para devs

### Entender o design?
→ [ARCHITECTURE.md](ARCHITECTURE.md) — Design técnico

### FAQ rápido?
→ [USAGE.md — FAQ](USAGE.md#-faq-rápido) — Perguntas frequentes

### Histórico de mudanças?
→ [CHANGELOG.md](../CHANGELOG.md) — Versões e features

---

## 💡 Quick Tips

```bash
# Instalação rápida
git clone https://github.com/seu-usuario/Licenses-Manager.git
cd Licenses-Manager
# Seguir SETUP.md

# Rodar o sistema
cd backend
go run cmd/cli/main.go

# Executar testes
go test ./tests/store -v

# Ver ajuda
# Menu interativo com opções
```

---

## 🗂️ Estrutura de Arquivos

```
Licenses-Manager/
├── README.md                    ← Start here!
├── CHANGELOG.md                 ← Histórico
├── docs/
│   ├── INDEX.md                 ← Você está aqui
│   ├── SETUP.md                 ← Instalação
│   ├── USAGE.md                 ← Como usar
│   ├── ARCHITECTURE.md          ← Design
│   └── CONTRIBUTING.md          ← Contribuir
├── backend/                     ← Código Go
├── frontend/                    ← Frontend (futuro)
├── database/                    ← Scripts SQL
└── tests/                       ← Testes
```

---

## ✨ Recursos

- **CLI Completa** — Gerenciar tudo via linha de comando
- **PostgreSQL** — Banco de dados relacional
- **Testes Unitários** — Cobertura de regras de negócio
- **Validações Forte** — Integridade de dados garantida

---

## 📞 Precisa de Ajuda?

1. **Procure no FAQ** — [USAGE.md](USAGE.md#-faq-rápido)
2. **Consulte Troubleshooting** — [SETUP.md](SETUP.md#-troubleshooting)
3. **Abra uma issue** — GitHub Issues
4. **Veja exemplos** — [USAGE.md](USAGE.md#-operações-básicas)

---

**Última atualização:** 2024
**Versão:** v1.0.0
**Status:** ✅ Pronto para uso