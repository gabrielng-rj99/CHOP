# Multi-stage build para frontend React
FROM node:18-alpine AS builder

WORKDIR /app

# Copiar package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copiar código
COPY . .

# Build
RUN npm run build

# Stage final - Nginx para servir arquivos estáticos
FROM nginx:alpine

# Remover configuração padrão
RUN rm -f /etc/nginx/conf.d/default.conf

# Copiar configuração customizada
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copiar build do stage anterior
COPY --from=builder /app/dist /usr/share/nginx/html

# Expor porta
EXPOSE 8081

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8081/ || exit 1

# Nginx command
CMD ["nginx", "-g", "daemon off;"]
