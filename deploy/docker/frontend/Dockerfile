# Multi-stage build para frontend (Vite)
FROM node:24-alpine AS builder

WORKDIR /build

# Copiar package files do frontend
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci

# Copiar código do frontend
COPY frontend/ ./

# Build application
RUN npm run build

# Stage final - Nginx para servir arquivos estáticos
FROM nginx:alpine

WORKDIR /app

# Remover configuração padrão do nginx
RUN rm -f /etc/nginx/conf.d/default.conf

# Copiar configuração customizada do nginx
COPY deploy/docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copiar build do stage anterior
COPY --from=builder /build/dist /usr/share/nginx/html

# Criar diretórios necessários
RUN mkdir -p /app/logs

# Expor porta (padrão 80, pode ser sobrescrito por NGINX_PORT env var)
EXPOSE 80

# Health check (use 127.0.0.1 to avoid IPv6 localhost issues)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1/health || exit 1

# Nginx command
CMD ["nginx", "-g", "daemon off;"]
