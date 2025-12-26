/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

-- ============================================
-- SYSTEM SETTINGS SEED DATA
-- ============================================
-- Este arquivo contém as configurações iniciais do sistema.
-- Separado do schema.sql para facilitar manutenção e atualizações futuras.
--
-- Categorias de configuração:
--   - security: Configurações de segurança (bloqueio, senha, sessão)
--   - theme: Permissões de tema
--   - dashboard: Configurações do painel principal
--   - notifications: Configurações de notificações
--   - audit: Configurações de auditoria
--
-- Execute após schema.sql

-- ============================================
-- THEME PERMISSIONS
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('permissions.users_can_edit_theme', 'false', 'Permite que usuários comuns personalizem seu tema', 'theme')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('permissions.admins_can_edit_theme', 'true', 'Permite que administradores personalizem seu tema', 'theme')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SECURITY: BLOQUEIO DE LOGIN (Multi-nível)
-- ============================================
-- O sistema usa bloqueio progressivo:
-- Nível 1: Bloqueio curto após poucas tentativas
-- Nível 2: Bloqueio médio após mais tentativas
-- Nível 3: Bloqueio longo após muitas tentativas
-- Manual: Bloqueio permanente requer desbloqueio por admin

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_1_attempts', '3', 'Tentativas de login para ativar bloqueio nível 1', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_1_duration', '300', 'Duração do bloqueio nível 1 em segundos (5 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_2_attempts', '5', 'Tentativas de login para ativar bloqueio nível 2', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_2_duration', '900', 'Duração do bloqueio nível 2 em segundos (15 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_3_attempts', '10', 'Tentativas de login para ativar bloqueio nível 3', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_3_duration', '3600', 'Duração do bloqueio nível 3 em segundos (60 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_manual_attempts', '15', 'Tentativas para bloqueio permanente (requer desbloqueio manual)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- Legacy settings (mantidos para compatibilidade)
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.login_block_time', '300', '[Legacy] Tempo de bloqueio padrão em segundos', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.login_attempts', '5', '[Legacy] Tentativas antes do bloqueio', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SECURITY: POLÍTICA DE SENHA (Global)
-- ============================================
-- Configurações globais de senha.
-- Para políticas por role, veja a tabela role_password_policies

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_min_length', '8', 'Tamanho mínimo da senha (padrão global, range: 8-128)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_max_length', '128', 'Tamanho máximo da senha (padrão global, range: 8-256)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_uppercase', 'true', 'Exigir pelo menos uma letra maiúscula', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_lowercase', 'true', 'Exigir pelo menos uma letra minúscula', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_numbers', 'true', 'Exigir pelo menos um número', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_special', 'true', 'Exigir pelo menos um caractere especial (!@#$%^&*...)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_max_age_days', '0', 'Dias para expiração da senha (0 = nunca expira)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_history_count', '0', 'Número de senhas anteriores que não podem ser reutilizadas (0 = desabilitado)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- PASSWORD ENTROPY (Informativo - não é limite de segurança)
-- ============================================
-- A entropia é calculada como: min_length * log2(charset_size)
-- Exemplo com política root (24 chars, todos os tipos):
--   charset_size = 26 (lower) + 26 (upper) + 10 (digits) + 32 (special) = 94
--   entropy = 24 * log2(94) = 24 * 6.55 ≈ 157 bits
--
-- Para referência de força:
--   < 50 bits: Fraca
--   50-90 bits: Básica
--   90-120 bits: Média
--   120-160 bits: Forte
--   > 160 bits: Muito Forte

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_entropy_min_bits', '90', 'Entropia mínima recomendada em bits (apenas para UI/info, não é obrigatório)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SECURITY: SESSÃO E JWT
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.session_duration', '60', 'Duração do token de acesso em minutos', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.refresh_token_duration', '10080', 'Duração do refresh token em minutos (padrão: 7 dias)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.single_session', 'false', 'Permitir apenas uma sessão ativa por usuário', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SECURITY: RATE LIMITING
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.rate_limit', '5', 'Limite de requisições por segundo por IP', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.rate_burst', '10', 'Burst máximo de requisições permitido', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- DASHBOARD: CONFIGURAÇÕES DE EXIBIÇÃO
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_birthdays', 'true', 'Exibir widget de aniversariantes no dashboard', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.birthdays_days_ahead', '7', 'Mostrar aniversariantes dos próximos X dias', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_recent_activity', 'true', 'Exibir widget de atividade recente', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.recent_activity_count', '10', 'Número de itens de atividade recente a exibir', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_statistics', 'true', 'Exibir widget de estatísticas (totais de entidades, acordos, etc)', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_expiring_agreements', 'true', 'Exibir widget de acordos próximos ao vencimento', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.expiring_days_ahead', '30', 'Mostrar acordos que vencem nos próximos X dias', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_quick_actions', 'true', 'Exibir botões de ações rápidas no dashboard', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- NOTIFICATIONS: CONFIGURAÇÕES GERAIS
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.email', '', 'E-mail para notificações do sistema (vazio = desabilitado)', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.phone', '', 'Telefone para notificações SMS (vazio = desabilitado)', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_login_failure', 'false', 'Enviar notificação em tentativas de login falhas', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_user_blocked', 'true', 'Enviar notificação quando um usuário for bloqueado', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_agreement_expiry', 'true', 'Enviar notificação quando acordos estiverem próximos ao vencimento', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- AUDIT: CONFIGURAÇÕES DE AUDITORIA
-- ============================================

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.retention_days', '365', 'Dias para manter logs de auditoria (0 = manter para sempre)', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_reads', 'false', 'Registrar operações de leitura no log (aumenta volume de dados)', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_login_success', 'true', 'Registrar logins bem-sucedidos', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_login_failure', 'true', 'Registrar tentativas de login falhas', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- DOCUMENTAÇÃO
-- ============================================
--
-- Para adicionar uma nova configuração:
-- 1. Escolha uma categoria apropriada (security, theme, dashboard, notifications, audit)
-- 2. Use um key no formato: categoria.nome_config
-- 3. O value é sempre string - converta no backend conforme necessário
-- 4. Adicione uma description clara em português
--
-- Valores especiais:
-- - Booleanos: 'true' ou 'false' (string)
-- - Números: '123' (string que será parseada)
-- - Listas: 'item1,item2,item3' (CSV string)
-- - JSON: '{"key": "value"}' (para configs complexas)
--
-- Para atualizar uma configuração existente em produção:
-- UPDATE system_settings SET value = 'novo_valor', updated_at = CURRENT_TIMESTAMP WHERE key = 'categoria.config';
