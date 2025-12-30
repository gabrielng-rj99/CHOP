/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

import React, { useState, useEffect } from "react";
import "./SecuritySettings.css";
import RolePasswordPolicies from "./RolePasswordPolicies";

export default function SecuritySettings({ token, apiUrl }) {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");
    const [activeTab, setActiveTab] = useState("lockLevels");

    // Security configuration state
    const [config, setConfig] = useState({
        // Lock Levels
        lockLevel1Attempts: 3,
        lockLevel1Duration: 300,
        lockLevel2Attempts: 5,
        lockLevel2Duration: 900,
        lockLevel3Attempts: 10,
        lockLevel3Duration: 3600,
        lockManualAttempts: 15,

        // Password Policy
        passwordMinLength: 16,
        passwordRequireUppercase: true,
        passwordRequireLowercase: true,
        passwordRequireNumbers: true,
        passwordRequireSpecial: true,

        // Session
        sessionDuration: 60,
        refreshTokenDuration: 10080,

        // Rate Limiting
        rateLimit: 5,
        rateBurst: 10,

        // Audit
        auditRetentionDays: 365,
        auditLogReads: false,

        // Notifications
        notificationEmail: "",
        notificationPhone: "",
    });

    useEffect(() => {
        loadConfig();
    }, []);

    const loadConfig = async () => {
        try {
            setLoading(true);
            const response = await fetch(`${apiUrl}/settings/security`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                setConfig({
                    lockLevel1Attempts: data.lock_level_1_attempts || 3,
                    lockLevel1Duration: data.lock_level_1_duration || 300,
                    lockLevel2Attempts: data.lock_level_2_attempts || 5,
                    lockLevel2Duration: data.lock_level_2_duration || 900,
                    lockLevel3Attempts: data.lock_level_3_attempts || 10,
                    lockLevel3Duration: data.lock_level_3_duration || 3600,
                    lockManualAttempts: data.lock_manual_attempts || 15,
                    passwordMinLength: data.password_min_length || 16,
                    passwordRequireUppercase:
                        data.password_require_uppercase ?? true,
                    passwordRequireLowercase:
                        data.password_require_lowercase ?? true,
                    passwordRequireNumbers:
                        data.password_require_numbers ?? true,
                    passwordRequireSpecial:
                        data.password_require_special ?? true,
                    sessionDuration: data.session_duration || 60,
                    refreshTokenDuration: data.refresh_token_duration || 10080,
                    rateLimit: data.rate_limit || 5,
                    rateBurst: data.rate_burst || 10,
                    auditRetentionDays: data.audit_retention_days || 365,
                    auditLogReads: data.audit_log_reads ?? false,
                    notificationEmail: data.notification_email || "",
                    notificationPhone: data.notification_phone || "",
                });
            } else {
                setError("Erro ao carregar configurações de segurança");
            }
        } catch (err) {
            console.error("Error loading security config:", err);
            setError("Erro ao carregar configurações de segurança");
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        setMessage("");
        setError("");
        setSaving(true);

        try {
            const response = await fetch(`${apiUrl}/settings/security`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                    lock_level_1_attempts: parseInt(
                        config.lockLevel1Attempts,
                        10,
                    ),
                    lock_level_1_duration: parseInt(
                        config.lockLevel1Duration,
                        10,
                    ),
                    lock_level_2_attempts: parseInt(
                        config.lockLevel2Attempts,
                        10,
                    ),
                    lock_level_2_duration: parseInt(
                        config.lockLevel2Duration,
                        10,
                    ),
                    lock_level_3_attempts: parseInt(
                        config.lockLevel3Attempts,
                        10,
                    ),
                    lock_level_3_duration: parseInt(
                        config.lockLevel3Duration,
                        10,
                    ),
                    lock_manual_attempts: parseInt(
                        config.lockManualAttempts,
                        10,
                    ),
                    password_min_length: parseInt(config.passwordMinLength, 10),
                    password_require_uppercase: config.passwordRequireUppercase,
                    password_require_lowercase: config.passwordRequireLowercase,
                    password_require_numbers: config.passwordRequireNumbers,
                    password_require_special: config.passwordRequireSpecial,
                    session_duration: parseInt(config.sessionDuration, 10),
                    refresh_token_duration: parseInt(
                        config.refreshTokenDuration,
                        10,
                    ),
                    rate_limit: parseInt(config.rateLimit, 10),
                    rate_burst: parseInt(config.rateBurst, 10),
                    audit_retention_days: parseInt(
                        config.auditRetentionDays,
                        10,
                    ),
                    audit_log_reads: config.auditLogReads,
                    notification_email: config.notificationEmail,
                    notification_phone: config.notificationPhone,
                }),
            });

            if (response.ok) {
                setMessage("Configurações de segurança salvas com sucesso!");
            } else {
                const data = await response.json();
                setError(data.error || "Erro ao salvar configurações");
            }
        } catch (err) {
            console.error("Error saving security config:", err);
            setError("Erro ao salvar configurações. Tente novamente.");
        } finally {
            setSaving(false);
        }
    };

    const handleChange = (key, value) => {
        setConfig((prev) => ({
            ...prev,
            [key]: value,
        }));
    };

    const formatDuration = (seconds) => {
        if (seconds === 0) return "0s";

        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}min`);
        if (secs > 0) parts.push(`${secs}s`);

        return parts.join(" ");
    };

    if (loading) {
        return (
            <div className="security-settings-loading">
                <div className="spinner"></div>
                <p>Carregando configurações de segurança...</p>
            </div>
        );
    }

    return (
        <div className="security-settings">
            <div className="security-settings-header">
                <h2>🔒 Configurações de Segurança</h2>
                <p className="security-description">
                    Configure as políticas de segurança do sistema, incluindo
                    bloqueio de contas, requisitos de senha e limitação de taxa.
                </p>
            </div>

            {message && <div className="security-success">{message}</div>}
            {error && <div className="security-error">{error}</div>}

            <div className="security-tabs">
                <button
                    className={`security-tab ${activeTab === "lockLevels" ? "active" : ""}`}
                    onClick={() => setActiveTab("lockLevels")}
                >
                    🔐 Bloqueio de Conta
                </button>
                <button
                    className={`security-tab ${activeTab === "password" ? "active" : ""}`}
                    onClick={() => setActiveTab("password")}
                >
                    🔑 Política de Senha
                </button>
                <button
                    className={`security-tab ${activeTab === "session" ? "active" : ""}`}
                    onClick={() => setActiveTab("session")}
                >
                    ⏱️ Sessão
                </button>
                <button
                    className={`security-tab ${activeTab === "rateLimit" ? "active" : ""}`}
                    onClick={() => setActiveTab("rateLimit")}
                >
                    🚦 Rate Limiting
                </button>
                <button
                    className={`security-tab ${activeTab === "audit" ? "active" : ""}`}
                    onClick={() => setActiveTab("audit")}
                >
                    📋 Auditoria
                </button>
            </div>

            <div className="security-content">
                {/* Lock Levels Tab */}
                {activeTab === "lockLevels" && (
                    <div className="security-section">
                        <h3>Sistema de Bloqueio Progressivo</h3>
                        <p className="section-info">
                            O sistema bloqueia contas progressivamente após
                            múltiplas tentativas de login falhas. Cada nível
                            aumenta o tempo de bloqueio.
                        </p>

                        <div className="lock-levels-grid">
                            {/* Level 1 */}
                            <div className="lock-level-card">
                                <div className="lock-level-header">
                                    <span className="level-badge level-1">
                                        Nível 1
                                    </span>
                                    <span className="level-duration">
                                        {formatDuration(
                                            config.lockLevel1Duration,
                                        )}
                                    </span>
                                </div>
                                <div className="lock-level-fields">
                                    <div className="field-group">
                                        <label>Tentativas</label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="20"
                                            value={config.lockLevel1Attempts}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel1Attempts",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                    <div className="field-group">
                                        <label>Duração (segundos)</label>
                                        <input
                                            type="number"
                                            min="60"
                                            max="3600"
                                            value={config.lockLevel1Duration}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel1Duration",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                </div>
                                <p className="level-description">
                                    Bloqueio inicial após{" "}
                                    {config.lockLevel1Attempts} tentativas
                                </p>
                            </div>

                            {/* Level 2 */}
                            <div className="lock-level-card">
                                <div className="lock-level-header">
                                    <span className="level-badge level-2">
                                        Nível 2
                                    </span>
                                    <span className="level-duration">
                                        {formatDuration(
                                            config.lockLevel2Duration,
                                        )}
                                    </span>
                                </div>
                                <div className="lock-level-fields">
                                    <div className="field-group">
                                        <label>Tentativas</label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="30"
                                            value={config.lockLevel2Attempts}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel2Attempts",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                    <div className="field-group">
                                        <label>Duração (segundos)</label>
                                        <input
                                            type="number"
                                            min="60"
                                            max="7200"
                                            value={config.lockLevel2Duration}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel2Duration",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                </div>
                                <p className="level-description">
                                    Bloqueio médio após{" "}
                                    {config.lockLevel2Attempts} tentativas
                                </p>
                            </div>

                            {/* Level 3 */}
                            <div className="lock-level-card">
                                <div className="lock-level-header">
                                    <span className="level-badge level-3">
                                        Nível 3
                                    </span>
                                    <span className="level-duration">
                                        {formatDuration(
                                            config.lockLevel3Duration,
                                        )}
                                    </span>
                                </div>
                                <div className="lock-level-fields">
                                    <div className="field-group">
                                        <label>Tentativas</label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="50"
                                            value={config.lockLevel3Attempts}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel3Attempts",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                    <div className="field-group">
                                        <label>Duração (segundos)</label>
                                        <input
                                            type="number"
                                            min="60"
                                            max="86400"
                                            value={config.lockLevel3Duration}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockLevel3Duration",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                </div>
                                <p className="level-description">
                                    Bloqueio severo após{" "}
                                    {config.lockLevel3Attempts} tentativas
                                </p>
                            </div>

                            {/* Manual Lock */}
                            <div className="lock-level-card manual">
                                <div className="lock-level-header">
                                    <span className="level-badge level-manual">
                                        Bloqueio Manual
                                    </span>
                                    <span className="level-duration">
                                        Permanente
                                    </span>
                                </div>
                                <div className="lock-level-fields">
                                    <div className="field-group full-width">
                                        <label>
                                            Tentativas para bloqueio permanente
                                        </label>
                                        <input
                                            type="number"
                                            min="10"
                                            max="100"
                                            value={config.lockManualAttempts}
                                            onChange={(e) =>
                                                handleChange(
                                                    "lockManualAttempts",
                                                    e.target.value,
                                                )
                                            }
                                        />
                                    </div>
                                </div>
                                <p className="level-description warning">
                                    ⚠️ Após {config.lockManualAttempts}{" "}
                                    tentativas, a conta é bloqueada
                                    permanentemente e requer desbloqueio manual
                                    por um administrador.
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Password Policy Tab */}
                {activeTab === "password" && (
                    <div className="security-section">
                        {/* Role-based Password Policies Component */}
                        <RolePasswordPolicies token={token} apiUrl={apiUrl} />

                        <div className="password-policy-divider">
                            <span>Configurações Globais (Fallback)</span>
                        </div>

                        <div className="global-policy-section">
                            <h3>🌐 Política de Senha Global</h3>
                            <p className="section-info">
                                Estas configurações são aplicadas quando um role
                                não possui política específica definida acima.
                            </p>
                        </div>

                        <div className="password-policy-grid">
                            <div className="policy-card">
                                <div className="policy-header">
                                    <label>Tamanho Mínimo</label>
                                    <span className="policy-value">
                                        {config.passwordMinLength} caracteres
                                    </span>
                                </div>
                                <input
                                    type="range"
                                    min="8"
                                    max="64"
                                    value={config.passwordMinLength}
                                    onChange={(e) =>
                                        handleChange(
                                            "passwordMinLength",
                                            e.target.value,
                                        )
                                    }
                                    className="policy-slider"
                                />
                                <div className="slider-labels">
                                    <span>8</span>
                                    <span>64</span>
                                </div>
                            </div>

                            <div className="policy-toggles">
                                <div className="policy-toggle">
                                    <label className="toggle-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                config.passwordRequireUppercase
                                            }
                                            onChange={(e) =>
                                                handleChange(
                                                    "passwordRequireUppercase",
                                                    e.target.checked,
                                                )
                                            }
                                        />
                                        <span className="toggle-switch"></span>
                                        <span className="toggle-text">
                                            Exigir letra maiúscula (A-Z)
                                        </span>
                                    </label>
                                </div>

                                <div className="policy-toggle">
                                    <label className="toggle-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                config.passwordRequireLowercase
                                            }
                                            onChange={(e) =>
                                                handleChange(
                                                    "passwordRequireLowercase",
                                                    e.target.checked,
                                                )
                                            }
                                        />
                                        <span className="toggle-switch"></span>
                                        <span className="toggle-text">
                                            Exigir letra minúscula (a-z)
                                        </span>
                                    </label>
                                </div>

                                <div className="policy-toggle">
                                    <label className="toggle-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                config.passwordRequireNumbers
                                            }
                                            onChange={(e) =>
                                                handleChange(
                                                    "passwordRequireNumbers",
                                                    e.target.checked,
                                                )
                                            }
                                        />
                                        <span className="toggle-switch"></span>
                                        <span className="toggle-text">
                                            Exigir número (0-9)
                                        </span>
                                    </label>
                                </div>

                                <div className="policy-toggle">
                                    <label className="toggle-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                config.passwordRequireSpecial
                                            }
                                            onChange={(e) =>
                                                handleChange(
                                                    "passwordRequireSpecial",
                                                    e.target.checked,
                                                )
                                            }
                                        />
                                        <span className="toggle-switch"></span>
                                        <span className="toggle-text">
                                            Exigir caractere especial (!@#$%^&*)
                                        </span>
                                    </label>
                                </div>
                            </div>

                            <div className="password-preview">
                                <h4>Exemplo de senha válida:</h4>
                                <code className="password-example">
                                    {generatePasswordExample(config)}
                                </code>
                            </div>
                        </div>
                    </div>
                )}

                {/* Session Tab */}
                {activeTab === "session" && (
                    <div className="security-section">
                        <h3>Configurações de Sessão</h3>
                        <p className="section-info">
                            Configure a duração das sessões de usuário. Sessões
                            mais curtas são mais seguras, mas menos
                            convenientes.
                        </p>

                        <div className="session-grid">
                            <div className="session-card">
                                <div className="session-icon">🎫</div>
                                <h4>Duração da Sessão</h4>
                                <p className="session-description">
                                    Tempo que o usuário permanece logado sem
                                    atividade.
                                </p>
                                <div className="session-input">
                                    <input
                                        type="number"
                                        min="5"
                                        max="1440"
                                        value={config.sessionDuration}
                                        onChange={(e) =>
                                            handleChange(
                                                "sessionDuration",
                                                e.target.value,
                                            )
                                        }
                                    />
                                    <span className="input-suffix">
                                        minutos
                                    </span>
                                </div>
                                <p className="session-hint">
                                    Equivale a{" "}
                                    {config.sessionDuration >= 60
                                        ? `${Math.floor(config.sessionDuration / 60)}h ${config.sessionDuration % 60}min`
                                        : `${config.sessionDuration} minutos`}
                                </p>
                            </div>

                            <div className="session-card">
                                <div className="session-icon">🔄</div>
                                <h4>Refresh Token</h4>
                                <p className="session-description">
                                    Tempo máximo que a sessão pode ser renovada
                                    automaticamente.
                                </p>
                                <div className="session-input">
                                    <input
                                        type="number"
                                        min="60"
                                        max="43200"
                                        value={config.refreshTokenDuration}
                                        onChange={(e) =>
                                            handleChange(
                                                "refreshTokenDuration",
                                                e.target.value,
                                            )
                                        }
                                    />
                                    <span className="input-suffix">
                                        minutos
                                    </span>
                                </div>
                                <p className="session-hint">
                                    Equivale a{" "}
                                    {Math.floor(
                                        config.refreshTokenDuration / 1440,
                                    )}{" "}
                                    dias e{" "}
                                    {Math.floor(
                                        (config.refreshTokenDuration % 1440) /
                                            60,
                                    )}{" "}
                                    horas
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Rate Limiting Tab */}
                {activeTab === "rateLimit" && (
                    <div className="security-section">
                        <h3>Limitação de Taxa (Rate Limiting)</h3>
                        <p className="section-info">
                            Proteja o sistema contra ataques de força bruta e
                            abuso de API limitando o número de requisições por
                            segundo.
                        </p>

                        <div className="rate-limit-grid">
                            <div className="rate-limit-card">
                                <div className="rate-icon">📊</div>
                                <h4>Limite de Requisições</h4>
                                <p>
                                    Número máximo de requisições por segundo por
                                    IP.
                                </p>
                                <div className="rate-input">
                                    <input
                                        type="number"
                                        min="1"
                                        max="100"
                                        value={config.rateLimit}
                                        onChange={(e) =>
                                            handleChange(
                                                "rateLimit",
                                                e.target.value,
                                            )
                                        }
                                    />
                                    <span className="input-suffix">req/s</span>
                                </div>
                            </div>

                            <div className="rate-limit-card">
                                <div className="rate-icon">💥</div>
                                <h4>Burst Máximo</h4>
                                <p>Pico de requisições permitido em rajada.</p>
                                <div className="rate-input">
                                    <input
                                        type="number"
                                        min="1"
                                        max="200"
                                        value={config.rateBurst}
                                        onChange={(e) =>
                                            handleChange(
                                                "rateBurst",
                                                e.target.value,
                                            )
                                        }
                                    />
                                    <span className="input-suffix">
                                        requisições
                                    </span>
                                </div>
                            </div>
                        </div>

                        <div className="rate-limit-info">
                            <h4>ℹ️ Como funciona</h4>
                            <p>
                                O sistema permite até{" "}
                                <strong>{config.rateLimit}</strong> requisições
                                por segundo de forma sustentada. Em momentos de
                                pico, é permitido um burst de até{" "}
                                <strong>{config.rateBurst}</strong> requisições.
                                Após exceder o limite, novas requisições serão
                                rejeitadas com status HTTP 429.
                            </p>
                        </div>
                    </div>
                )}

                {/* Audit Tab */}
                {activeTab === "audit" && (
                    <div className="security-section">
                        <h3>Configurações de Auditoria</h3>
                        <p className="section-info">
                            Configure como os logs de auditoria são gerenciados
                            e armazenados.
                        </p>

                        <div className="audit-grid">
                            <div className="audit-card">
                                <h4>📅 Retenção de Logs</h4>
                                <p>
                                    Tempo que os logs de auditoria são mantidos
                                    no sistema.
                                </p>
                                <div className="audit-input">
                                    <input
                                        type="number"
                                        min="30"
                                        max="3650"
                                        value={config.auditRetentionDays}
                                        onChange={(e) =>
                                            handleChange(
                                                "auditRetentionDays",
                                                e.target.value,
                                            )
                                        }
                                    />
                                    <span className="input-suffix">dias</span>
                                </div>
                                <p className="audit-hint">
                                    Equivale a aproximadamente{" "}
                                    {Math.round(config.auditRetentionDays / 30)}{" "}
                                    meses
                                </p>
                            </div>

                            <div className="audit-card">
                                <h4>📖 Registrar Leituras</h4>
                                <p>
                                    Se ativado, operações de leitura (GET)
                                    também serão registradas no log de
                                    auditoria.
                                </p>
                                <div className="audit-toggle">
                                    <label className="toggle-label">
                                        <input
                                            type="checkbox"
                                            checked={config.auditLogReads}
                                            onChange={(e) =>
                                                handleChange(
                                                    "auditLogReads",
                                                    e.target.checked,
                                                )
                                            }
                                        />
                                        <span className="toggle-switch"></span>
                                        <span className="toggle-text">
                                            {config.auditLogReads
                                                ? "Ativado (mais logs, mais espaço)"
                                                : "Desativado (recomendado)"}
                                        </span>
                                    </label>
                                </div>
                                <p className="audit-warning">
                                    ⚠️ Ativar esta opção pode aumentar
                                    significativamente o tamanho do banco de
                                    dados.
                                </p>
                            </div>
                        </div>

                        <div className="notifications-section">
                            <h4>📧 Notificações (Em breve)</h4>
                            <p>
                                Configure notificações para eventos de segurança
                                importantes.
                            </p>

                            <div className="notifications-grid">
                                <div className="notification-field">
                                    <label>E-mail para notificações</label>
                                    <input
                                        type="email"
                                        placeholder="admin@exemplo.com"
                                        value={config.notificationEmail}
                                        onChange={(e) =>
                                            handleChange(
                                                "notificationEmail",
                                                e.target.value,
                                            )
                                        }
                                        disabled
                                    />
                                    <span className="coming-soon">
                                        Em breve
                                    </span>
                                </div>

                                <div className="notification-field">
                                    <label>Telefone para notificações</label>
                                    <input
                                        type="tel"
                                        placeholder="+55 11 99999-9999"
                                        value={config.notificationPhone}
                                        onChange={(e) =>
                                            handleChange(
                                                "notificationPhone",
                                                e.target.value,
                                            )
                                        }
                                        disabled
                                    />
                                    <span className="coming-soon">
                                        Em breve
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <div className="security-actions">
                <button
                    className="security-save-button"
                    onClick={handleSave}
                    disabled={saving}
                >
                    {saving
                        ? "Salvando..."
                        : "💾 Salvar Configurações de Segurança"}
                </button>
            </div>
        </div>
    );
}

// Helper function to generate a password example based on policy
function generatePasswordExample(config) {
    let example = "";
    const length = Math.max(config.passwordMinLength, 8);

    if (config.passwordRequireUppercase) example += "Abc";
    if (config.passwordRequireLowercase) example += "def";
    if (config.passwordRequireNumbers) example += "123";
    if (config.passwordRequireSpecial) example += "!@#";

    // Pad to minimum length
    while (example.length < length) {
        example += "x";
    }

    return example.substring(0, Math.max(length, example.length));
}
