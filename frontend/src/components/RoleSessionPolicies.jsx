/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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
import "./RoleSessionPolicies.css";

export default function RoleSessionPolicies({ token, apiUrl }) {
    const [loading, setLoading] = useState(true);
    const [policies, setPolicies] = useState([]);
    const [editingPolicy, setEditingPolicy] = useState(null);
    const [showEditModal, setShowEditModal] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");

    useEffect(() => {
        loadPolicies();
    }, []);

    const loadPolicies = async () => {
        try {
            setLoading(true);
            setError("");
            const response = await fetch(`${apiUrl}/roles/session-policies`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                setPolicies(data || []);
            } else {
                const errorData = await response.json();
                setError(errorData.error || "Erro ao carregar políticas");
            }
        } catch (err) {
            setError("Erro ao conectar com o servidor");
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (policy) => {
        setEditingPolicy({
            role_id: policy.role_id,
            role_name: policy.role_name,
            session_duration_minutes: policy.session_duration_minutes,
            refresh_token_duration_minutes:
                policy.refresh_token_duration_minutes,
            max_concurrent_sessions: policy.max_concurrent_sessions || "",
            idle_timeout_minutes: policy.idle_timeout_minutes || "",
            require_2fa: policy.require_2fa,
        });
        setShowEditModal(true);
        setError("");
        setMessage("");
    };

    const handleSave = async () => {
        try {
            setError("");
            setMessage("");

            // Validate
            if (
                editingPolicy.session_duration_minutes < 5 ||
                editingPolicy.session_duration_minutes > 1440
            ) {
                setError("Duração de sessão deve estar entre 5 e 1440 minutos");
                return;
            }

            if (
                editingPolicy.refresh_token_duration_minutes < 60 ||
                editingPolicy.refresh_token_duration_minutes > 525600
            ) {
                setError(
                    "Duração de refresh token deve estar entre 60 minutos e 365 dias",
                );
                return;
            }

            const payload = {
                session_duration_minutes: parseInt(
                    editingPolicy.session_duration_minutes,
                ),
                refresh_token_duration_minutes: parseInt(
                    editingPolicy.refresh_token_duration_minutes,
                ),
                max_concurrent_sessions:
                    editingPolicy.max_concurrent_sessions !== ""
                        ? parseInt(editingPolicy.max_concurrent_sessions)
                        : null,
                idle_timeout_minutes:
                    editingPolicy.idle_timeout_minutes !== ""
                        ? parseInt(editingPolicy.idle_timeout_minutes)
                        : null,
                require_2fa: editingPolicy.require_2fa,
            };

            const response = await fetch(
                `${apiUrl}/roles/${editingPolicy.role_id}/session-policy`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(payload),
                },
            );

            if (response.ok) {
                setMessage("Política de sessão atualizada com sucesso!");
                setShowEditModal(false);
                setEditingPolicy(null);
                loadPolicies();
            } else {
                const errorData = await response.json();
                setError(errorData.error || "Erro ao salvar política");
            }
        } catch (err) {
            setError("Erro ao conectar com o servidor");
            console.error(err);
        }
    };

    const formatDuration = (minutes) => {
        if (minutes < 60) {
            return `${minutes} minuto${minutes !== 1 ? "s" : ""}`;
        } else if (minutes < 1440) {
            const hours = Math.floor(minutes / 60);
            const mins = minutes % 60;
            if (mins === 0) {
                return `${hours} hora${hours !== 1 ? "s" : ""}`;
            }
            return `${hours}h ${mins}min`;
        } else {
            const days = Math.floor(minutes / 1440);
            const hours = Math.floor((minutes % 1440) / 60);
            if (hours === 0) {
                return `${days} dia${days !== 1 ? "s" : ""}`;
            }
            return `${days}d ${hours}h`;
        }
    };

    const getRoleBadgeClass = (roleName) => {
        switch (roleName) {
            case "root":
                return "role-badge-root";
            case "admin":
                return "role-badge-admin";
            case "user":
                return "role-badge-user";
            case "viewer":
                return "role-badge-viewer";
            default:
                return "role-badge-custom";
        }
    };

    const getSecurityLevel = (policy) => {
        let score = 0;

        // Shorter session = more secure
        if (policy.session_duration_minutes <= 30) score += 3;
        else if (policy.session_duration_minutes <= 60) score += 2;
        else if (policy.session_duration_minutes <= 240) score += 1;

        // Max sessions limit = more secure
        if (policy.max_concurrent_sessions === 1) score += 3;
        else if (policy.max_concurrent_sessions <= 3) score += 2;
        else if (policy.max_concurrent_sessions <= 5) score += 1;

        // Idle timeout = more secure
        if (policy.idle_timeout_minutes && policy.idle_timeout_minutes <= 30)
            score += 2;
        else if (
            policy.idle_timeout_minutes &&
            policy.idle_timeout_minutes <= 120
        )
            score += 1;

        // 2FA = more secure
        if (policy.require_2fa) score += 2;

        if (score >= 8) return { level: "Muito Alta", class: "security-high" };
        if (score >= 5) return { level: "Alta", class: "security-medium-high" };
        if (score >= 3) return { level: "Média", class: "security-medium" };
        return { level: "Padrão", class: "security-low" };
    };

    if (loading) {
        return (
            <div className="role-session-policies">
                <div className="loading-container">
                    <div className="spinner"></div>
                    <p>Carregando políticas de sessão...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="role-session-policies">
            <div className="policies-header">
                <div>
                    <h2>⏱️ Políticas de Sessão por Role</h2>
                    <p className="policies-description">
                        Configure a duração de sessões e tokens de atualização
                        para cada nível de usuário
                    </p>
                </div>
            </div>

            {message && (
                <div className="success-message">
                    <span className="success-icon">✓</span>
                    {message}
                </div>
            )}

            {error && !showEditModal && (
                <div className="error-message">
                    <span className="error-icon">⚠</span>
                    {error}
                </div>
            )}

            <div className="policies-grid">
                {policies.map((policy) => {
                    const security = getSecurityLevel(policy);
                    return (
                        <div key={policy.id} className="policy-card">
                            <div className="policy-card-header">
                                <div className="policy-role-info">
                                    <span
                                        className={`role-badge ${getRoleBadgeClass(policy.role_name)}`}
                                    >
                                        {policy.role_name.toUpperCase()}
                                    </span>
                                    <span
                                        className={`security-badge ${security.class}`}
                                    >
                                        🔒 {security.level}
                                    </span>
                                </div>
                                <button
                                    className="edit-button"
                                    onClick={() => handleEdit(policy)}
                                    title="Editar política"
                                >
                                    ✏️
                                </button>
                            </div>

                            <div className="policy-details">
                                <div className="policy-detail-item">
                                    <span className="detail-icon">🕐</span>
                                    <div className="detail-content">
                                        <span className="detail-label">
                                            Duração da Sessão
                                        </span>
                                        <span className="detail-value">
                                            {formatDuration(
                                                policy.session_duration_minutes,
                                            )}
                                        </span>
                                    </div>
                                </div>

                                <div className="policy-detail-item">
                                    <span className="detail-icon">🔄</span>
                                    <div className="detail-content">
                                        <span className="detail-label">
                                            Refresh Token
                                        </span>
                                        <span className="detail-value">
                                            {formatDuration(
                                                policy.refresh_token_duration_minutes,
                                            )}
                                        </span>
                                    </div>
                                </div>

                                <div className="policy-detail-item">
                                    <span className="detail-icon">👥</span>
                                    <div className="detail-content">
                                        <span className="detail-label">
                                            Sessões Simultâneas
                                        </span>
                                        <span className="detail-value">
                                            {policy.max_concurrent_sessions ||
                                                "Ilimitado"}
                                        </span>
                                    </div>
                                </div>

                                <div className="policy-detail-item">
                                    <span className="detail-icon">💤</span>
                                    <div className="detail-content">
                                        <span className="detail-label">
                                            Timeout de Inatividade
                                        </span>
                                        <span className="detail-value">
                                            {policy.idle_timeout_minutes
                                                ? formatDuration(
                                                      policy.idle_timeout_minutes,
                                                  )
                                                : "Desabilitado"}
                                        </span>
                                    </div>
                                </div>

                                <div className="policy-detail-item">
                                    <span className="detail-icon">🔐</span>
                                    <div className="detail-content">
                                        <span className="detail-label">
                                            Autenticação 2FA
                                        </span>
                                        <span
                                            className={`detail-value ${policy.require_2fa ? "enabled" : "disabled"}`}
                                        >
                                            {policy.require_2fa
                                                ? "Obrigatório"
                                                : "Opcional"}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {showEditModal && editingPolicy && (
                <div className="modal-overlay">
                    <div className="modal-content modal-large">
                        <div className="modal-header">
                            <h3>
                                Editar Política de Sessão -{" "}
                                <span
                                    className={`role-badge ${getRoleBadgeClass(editingPolicy.role_name)}`}
                                >
                                    {editingPolicy.role_name.toUpperCase()}
                                </span>
                            </h3>
                            <button
                                className="close-button"
                                onClick={() => {
                                    setShowEditModal(false);
                                    setEditingPolicy(null);
                                    setError("");
                                }}
                            >
                                ✕
                            </button>
                        </div>

                        {error && (
                            <div className="modal-error">
                                <span className="error-icon">⚠</span>
                                {error}
                            </div>
                        )}

                        <div className="modal-body">
                            <div className="form-row">
                                <div className="form-group">
                                    <label>
                                        Duração da Sessão (minutos)
                                        <span className="required">*</span>
                                    </label>
                                    <input
                                        type="number"
                                        min="5"
                                        max="1440"
                                        value={
                                            editingPolicy.session_duration_minutes
                                        }
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                session_duration_minutes:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        Entre 5 minutos e 24 horas (
                                        {formatDuration(
                                            parseInt(
                                                editingPolicy.session_duration_minutes,
                                            ) || 0,
                                        )}
                                        )
                                    </span>
                                </div>

                                <div className="form-group">
                                    <label>
                                        Duração do Refresh Token (minutos)
                                        <span className="required">*</span>
                                    </label>
                                    <input
                                        type="number"
                                        min="60"
                                        max="525600"
                                        value={
                                            editingPolicy.refresh_token_duration_minutes
                                        }
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                refresh_token_duration_minutes:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        Entre 1 hora e 365 dias (
                                        {formatDuration(
                                            parseInt(
                                                editingPolicy.refresh_token_duration_minutes,
                                            ) || 0,
                                        )}
                                        )
                                    </span>
                                </div>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Sessões Simultâneas Máximas</label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="100"
                                        placeholder="Ilimitado"
                                        value={
                                            editingPolicy.max_concurrent_sessions
                                        }
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                max_concurrent_sessions:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        Deixe vazio para ilimitado
                                    </span>
                                </div>

                                <div className="form-group">
                                    <label>
                                        Timeout de Inatividade (minutos)
                                    </label>
                                    <input
                                        type="number"
                                        min="5"
                                        max="1440"
                                        placeholder="Desabilitado"
                                        value={
                                            editingPolicy.idle_timeout_minutes
                                        }
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                idle_timeout_minutes:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        {editingPolicy.idle_timeout_minutes
                                            ? `Sessão expira após ${formatDuration(parseInt(editingPolicy.idle_timeout_minutes) || 0)} sem atividade`
                                            : "Deixe vazio para desabilitar"}
                                    </span>
                                </div>
                            </div>

                            <div className="form-group">
                                <label className="checkbox-label">
                                    <input
                                        type="checkbox"
                                        checked={editingPolicy.require_2fa}
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                require_2fa: e.target.checked,
                                            })
                                        }
                                    />
                                    <span>
                                        Exigir Autenticação de Dois Fatores
                                        (2FA)
                                    </span>
                                </label>
                                <span className="form-hint">
                                    ⚠️ Usuários serão forçados a configurar 2FA
                                    no próximo login
                                </span>
                            </div>

                            <div className="info-box">
                                <div className="info-icon">ℹ️</div>
                                <div className="info-content">
                                    <strong>Recomendações de Segurança:</strong>
                                    <ul>
                                        <li>
                                            Sessões curtas para roles sensíveis
                                            (viewer, guest)
                                        </li>
                                        <li>
                                            Limite sessões simultâneas para
                                            prevenir compartilhamento de contas
                                        </li>
                                        <li>
                                            Use timeout de inatividade para
                                            roles com acesso a dados sensíveis
                                        </li>
                                        <li>
                                            Considere 2FA obrigatório para
                                            admins e root
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div className="modal-footer">
                            <button
                                className="button-cancel"
                                onClick={() => {
                                    setShowEditModal(false);
                                    setEditingPolicy(null);
                                    setError("");
                                }}
                            >
                                Cancelar
                            </button>
                            <button
                                className="button-save"
                                onClick={handleSave}
                            >
                                💾 Salvar Política
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
