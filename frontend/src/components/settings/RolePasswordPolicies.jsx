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

import React, { useState, useEffect, useCallback } from "react";
import "./RolePasswordPolicies.css";

export default function RolePasswordPolicies({ token, apiUrl }) {
    const [loading, setLoading] = useState(true);
    const [policies, setPolicies] = useState([]);
    const [editingPolicy, setEditingPolicy] = useState(null);
    const [showEditModal, setShowEditModal] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");
    const [saving, setSaving] = useState(false);
    const [expandedPolicies, setExpandedPolicies] = useState({});

    const toggleExpand = (roleId) => {
        setExpandedPolicies((prev) => ({
            ...prev,
            [roleId]: !prev[roleId],
        }));
    };

    const loadPolicies = useCallback(async () => {
        try {
            setLoading(true);
            setError("");
            const response = await fetch(`${apiUrl}/roles/password-policies`, {
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
    }, [apiUrl, token]);

    useEffect(() => {
        loadPolicies();
    }, [loadPolicies]);

    const handleEdit = (policy) => {
        setEditingPolicy({
            role_id: policy.role_id,
            role_name: policy.role_name,
            min_length: policy.min_length || 16,
            max_length: policy.max_length || 128,
            require_uppercase: policy.require_uppercase ?? true,
            require_lowercase: policy.require_lowercase ?? true,
            require_numbers: policy.require_numbers ?? true,
            require_special: policy.require_special ?? true,
            allowed_special_chars:
                policy.allowed_special_chars || "!@#$%^&*()_+-=[]{}|;:,.<>?",
            max_age_days: policy.max_age_days || 0,
            history_count: policy.history_count || 0,
            min_age_hours: policy.min_age_hours || 0,
            min_unique_chars: policy.min_unique_chars || 0,
            no_username_in_password: policy.no_username_in_password ?? true,
            no_common_passwords: policy.no_common_passwords ?? true,
            description: policy.description || "",
            is_active: policy.is_active,
        });
        setShowEditModal(true);
        setError("");
        setMessage("");
    };

    const handleSave = async () => {
        try {
            setError("");
            setMessage("");
            setSaving(true);

            // Validate
            if (
                editingPolicy.min_length < 8 ||
                editingPolicy.min_length > 128
            ) {
                setError(
                    "Tamanho mínimo de senha deve estar entre 8 e 128 caracteres",
                );
                setSaving(false);
                return;
            }

            if (editingPolicy.max_length < editingPolicy.min_length) {
                setError(
                    "Tamanho máximo deve ser maior ou igual ao tamanho mínimo",
                );
                setSaving(false);
                return;
            }

            const payload = {
                min_length: parseInt(editingPolicy.min_length),
                max_length: parseInt(editingPolicy.max_length),
                require_uppercase: editingPolicy.require_uppercase,
                require_lowercase: editingPolicy.require_lowercase,
                require_numbers: editingPolicy.require_numbers,
                require_special: editingPolicy.require_special,
                allowed_special_chars:
                    editingPolicy.allowed_special_chars || null,
                max_age_days:
                    editingPolicy.max_age_days !== ""
                        ? parseInt(editingPolicy.max_age_days)
                        : 0,
                history_count:
                    editingPolicy.history_count !== ""
                        ? parseInt(editingPolicy.history_count)
                        : 0,
                min_age_hours:
                    editingPolicy.min_age_hours !== ""
                        ? parseInt(editingPolicy.min_age_hours)
                        : 0,
                min_unique_chars:
                    editingPolicy.min_unique_chars !== ""
                        ? parseInt(editingPolicy.min_unique_chars)
                        : 0,
                no_username_in_password: editingPolicy.no_username_in_password,
                no_common_passwords: editingPolicy.no_common_passwords,
                description: editingPolicy.description || null,
            };

            const response = await fetch(
                `${apiUrl}/roles/${editingPolicy.role_id}/password-policy`,
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
                setMessage("Política de senha atualizada com sucesso!");
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
        } finally {
            setSaving(false);
        }
    };

    const handleResetToDefault = async (roleId, roleName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja remover a política personalizada do role "${roleName}"?\n\nEle passará a usar as configurações globais do sistema.`,
            )
        ) {
            return;
        }

        try {
            const response = await fetch(
                `${apiUrl}/roles/${roleId}/password-policy`,
                {
                    method: "DELETE",
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                },
            );

            if (response.ok) {
                setMessage(
                    `Política do role "${roleName}" removida. Usando configurações globais.`,
                );
                loadPolicies();
            } else {
                const errorData = await response.json();
                setError(errorData.error || "Erro ao remover política");
            }
        } catch (err) {
            setError("Erro ao conectar com o servidor");
            console.error(err);
        }
    };

    const getRoleBadgeClass = (roleName) => {
        const name = roleName?.toLowerCase();
        switch (name) {
            case "root":
                return "role-badge-root";
            case "admin":
                return "role-badge-admin";
            case "user":
                return "role-badge-user";
            case "viewer":
                return "role-badge-viewer";
            case "financeiro":
                return "role-badge-financeiro";
            default:
                return "role-badge-custom";
        }
    };

    const getStrengthLevel = (policy) => {
        let score = 0;

        // Length scoring
        if (policy.min_length >= 24) score += 4;
        else if (policy.min_length >= 20) score += 3;
        else if (policy.min_length >= 16) score += 2;
        else if (policy.min_length >= 12) score += 1;

        // Character requirements
        if (policy.require_uppercase) score += 1;
        if (policy.require_lowercase) score += 1;
        if (policy.require_numbers) score += 1;
        if (policy.require_special) score += 2;

        // Advanced features
        if (policy.max_age_days > 0 && policy.max_age_days <= 90) score += 2;
        else if (policy.max_age_days > 0 && policy.max_age_days <= 180)
            score += 1;

        if (policy.history_count >= 5) score += 2;
        else if (policy.history_count >= 3) score += 1;

        if (policy.min_age_hours > 0) score += 1;
        if (policy.min_unique_chars >= 8) score += 1;
        if (policy.no_username_in_password) score += 1;
        if (policy.no_common_passwords) score += 1;

        if (score >= 14)
            return { level: "Muito Forte", class: "strength-very-high" };
        if (score >= 10) return { level: "Forte", class: "strength-high" };
        if (score >= 6) return { level: "Média", class: "strength-medium" };
        if (score >= 3) return { level: "Básica", class: "strength-low" };
        return { level: "Fraca", class: "strength-very-low" };
    };

    const calculatePasswordScore = (policy) => {
        // Character set size
        let charsetSize = 0;
        if (policy.require_lowercase) charsetSize += 26;
        if (policy.require_uppercase) charsetSize += 26;
        if (policy.require_numbers) charsetSize += 10;
        if (policy.require_special) charsetSize += 32;

        // If nothing required, assume all
        if (charsetSize === 0) charsetSize = 94;

        // Entropy calculation: log2(charset^length)
        const entropy = policy.min_length * Math.log2(charsetSize);
        return Math.round(entropy);
    };

    const formatExpiration = (days) => {
        if (!days || days === 0) return "Nunca expira";
        if (days === 1) return "1 dia";
        if (days < 30) return `${days} dias`;
        if (days < 60) return "~1 mês";
        if (days < 90) return "~2 meses";
        if (days === 90) return "3 meses";
        if (days < 180) return `${Math.round(days / 30)} meses`;
        if (days === 180) return "6 meses";
        if (days === 365) return "1 ano";
        return `${days} dias`;
    };

    if (loading) {
        return (
            <div className="role-password-policies">
                <div className="loading-container">
                    <div className="spinner"></div>
                    <p>Carregando políticas de senha...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="role-password-policies">
            <div className="policies-header">
                <div>
                    <h2>🔐 Políticas de Senha por Role</h2>
                    <p className="policies-description">
                        Configure requisitos de senha específicos para cada
                        nível de usuário. Roles sem política personalizada usam
                        as configurações globais.
                    </p>
                </div>
            </div>

            {message && (
                <div className="success-message">
                    <span className="success-icon">✓</span>
                    {message}
                    <button
                        className="dismiss-btn"
                        onClick={() => setMessage("")}
                    >
                        ×
                    </button>
                </div>
            )}

            {error && !showEditModal && (
                <div className="error-message">
                    <span className="error-icon">⚠</span>
                    {error}
                    <button
                        className="dismiss-btn"
                        onClick={() => setError("")}
                    >
                        ×
                    </button>
                </div>
            )}

            <div className="policies-grid">
                {policies.map((policy) => {
                    const strength = getStrengthLevel(policy);
                    const entropy = calculatePasswordScore(policy);
                    return (
                        <div
                            key={policy.role_id}
                            className={`policy-card ${!policy.is_active ? "using-global" : ""}`}
                        >
                            <div
                                className={`policy-card-header ${expandedPolicies[policy.role_id] ? "expanded" : ""}`}
                                onClick={() => toggleExpand(policy.role_id)}
                                style={{ cursor: "pointer" }}
                            >
                                <div className="policy-role-info">
                                    <span
                                        className="expand-icon"
                                        style={{
                                            display: "inline-block",
                                            marginRight: "8px",
                                            transition: "transform 0.2s",
                                            transform: expandedPolicies[
                                                policy.role_id
                                            ]
                                                ? "rotate(90deg)"
                                                : "rotate(0deg)",
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                        }}
                                    >
                                        ▶
                                    </span>
                                    <span
                                        className={`role-badge ${getRoleBadgeClass(policy.role_name)}`}
                                    >
                                        {policy.role_name?.toUpperCase()}
                                    </span>
                                    <span
                                        className={`strength-badge ${strength.class}`}
                                    >
                                        🛡️ {strength.level}
                                    </span>
                                    {!policy.is_active && (
                                        <span className="global-badge">
                                            📋 Global
                                        </span>
                                    )}
                                </div>
                                <div className="policy-actions">
                                    {policy.is_active && (
                                        <button
                                            className="reset-button"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                handleResetToDefault(
                                                    policy.role_id,
                                                    policy.role_name,
                                                );
                                            }}
                                            title="Usar configurações globais"
                                        >
                                            🔄
                                        </button>
                                    )}
                                    <button
                                        className="edit-button"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            handleEdit(policy);
                                        }}
                                        title="Editar política"
                                    >
                                        ✏️
                                    </button>
                                </div>
                            </div>

                            {expandedPolicies[policy.role_id] && (
                                <div className="policy-details">
                                    <div className="policy-metrics-row">
                                        <div className="policy-metric">
                                            <div className="metric-header">
                                                <span className="metric-label">
                                                    Tamanho Mínimo
                                                </span>
                                                <span className="metric-value-large">
                                                    {policy.min_length}
                                                </span>
                                                <div className="metric-subtitle">
                                                    caracteres
                                                </div>
                                            </div>
                                        </div>

                                        <div className="policy-metric">
                                            <div className="metric-header">
                                                <span className="metric-label">
                                                    Entropia
                                                </span>
                                                <span className="metric-value-large">
                                                    {entropy}
                                                </span>
                                                <div className="metric-subtitle">
                                                    bits (estimado)
                                                </div>
                                            </div>
                                        </div>

                                        <div className="policy-metric">
                                            <div className="metric-header">
                                                <span className="metric-label">
                                                    Expiração
                                                </span>
                                                <span className="metric-value-small">
                                                    {formatExpiration(
                                                        policy.max_age_days,
                                                    )}
                                                </span>
                                                <div className="metric-subtitle">
                                                    de validade
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="requirements-section">
                                        <div className="requirements-title">
                                            Requisitos de Caracteres:
                                        </div>
                                        <div className="requirements-grid">
                                            <div
                                                className={`requirement-item ${policy.require_uppercase ? "enabled" : "disabled"}`}
                                            >
                                                <span className="req-icon">
                                                    {policy.require_uppercase
                                                        ? "✓"
                                                        : "✗"}
                                                </span>
                                                <span className="req-text">
                                                    Maiúsculas
                                                </span>
                                            </div>
                                            <div
                                                className={`requirement-item ${policy.require_lowercase ? "enabled" : "disabled"}`}
                                            >
                                                <span className="req-icon">
                                                    {policy.require_lowercase
                                                        ? "✓"
                                                        : "✗"}
                                                </span>
                                                <span className="req-text">
                                                    Minúsculas
                                                </span>
                                            </div>
                                            <div
                                                className={`requirement-item ${policy.require_numbers ? "enabled" : "disabled"}`}
                                            >
                                                <span className="req-icon">
                                                    {policy.require_numbers
                                                        ? "✓"
                                                        : "✗"}
                                                </span>
                                                <span className="req-text">
                                                    Números
                                                </span>
                                            </div>
                                            <div
                                                className={`requirement-item ${policy.require_special ? "enabled" : "disabled"}`}
                                            >
                                                <span className="req-icon">
                                                    {policy.require_special
                                                        ? "✓"
                                                        : "✗"}
                                                </span>
                                                <span className="req-text">
                                                    Especiais
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="advanced-rules">
                                        <div className="advanced-title">
                                            Regras Avançadas:
                                        </div>
                                        <div className="advanced-grid">
                                            <div className="advanced-item">
                                                <span className="adv-icon">
                                                    🔄
                                                </span>
                                                <span className="adv-text">
                                                    Histórico:{" "}
                                                    {policy.history_count > 0
                                                        ? `${policy.history_count} senhas`
                                                        : "Não"}
                                                </span>
                                            </div>
                                            <div className="advanced-item">
                                                <span className="adv-icon">
                                                    ⏱️
                                                </span>
                                                <span className="adv-text">
                                                    Intervalo:{" "}
                                                    {policy.min_age_hours > 0
                                                        ? `${policy.min_age_hours}h`
                                                        : "Sem limite"}
                                                </span>
                                            </div>
                                            <div className="advanced-item">
                                                <span className="adv-icon">
                                                    🔤
                                                </span>
                                                <span className="adv-text">
                                                    Únicos:{" "}
                                                    {policy.min_unique_chars > 0
                                                        ? `${policy.min_unique_chars} chars`
                                                        : "Não"}
                                                </span>
                                            </div>
                                            <div className="advanced-item">
                                                <span className="adv-icon">
                                                    {policy.no_common_passwords
                                                        ? "✅"
                                                        : "❌"}
                                                </span>
                                                <span className="adv-text">
                                                    Bloquear comuns
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            {/* Edit Modal */}
            {showEditModal && editingPolicy && (
                <div className="modal-overlay">
                    <div className="modal-content modal-large">
                        <div className="modal-header">
                            <h3>
                                Editar Política de Senha -{" "}
                                <span
                                    className={`role-badge ${getRoleBadgeClass(editingPolicy.role_name)}`}
                                >
                                    {editingPolicy.role_name?.toUpperCase()}
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
                            {/* Basic Requirements */}
                            <div className="form-section">
                                <h4 className="section-title">
                                    📏 Tamanho da Senha
                                </h4>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>
                                            Tamanho Mínimo
                                            <span className="required">*</span>
                                        </label>
                                        <input
                                            type="number"
                                            min="8"
                                            max="128"
                                            value={editingPolicy.min_length}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    min_length: e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            Entre 8 e 128 caracteres
                                        </span>
                                    </div>

                                    <div className="form-group">
                                        <label>Tamanho Máximo</label>
                                        <input
                                            type="number"
                                            min="8"
                                            max="256"
                                            value={editingPolicy.max_length}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    max_length: e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            Entre mínimo e 256 caracteres
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Character Requirements */}
                            <div className="form-section">
                                <h4 className="section-title">
                                    🔤 Requisitos de Caracteres
                                </h4>

                                <div className="checkboxes-grid">
                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.require_uppercase
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    require_uppercase:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>Exigir Maiúsculas (A-Z)</span>
                                    </label>

                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.require_lowercase
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    require_lowercase:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>Exigir Minúsculas (a-z)</span>
                                    </label>

                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.require_numbers
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    require_numbers:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>Exigir Números (0-9)</span>
                                    </label>

                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.require_special
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    require_special:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>Exigir Especiais (!@#$...)</span>
                                    </label>
                                </div>

                                {editingPolicy.require_special && (
                                    <div className="form-group">
                                        <label>
                                            Caracteres Especiais Permitidos
                                        </label>
                                        <input
                                            type="text"
                                            value={
                                                editingPolicy.allowed_special_chars
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    allowed_special_chars:
                                                        e.target.value,
                                                })
                                            }
                                            placeholder="!@#$%^&*()_+-=[]{}|;:,.<>?"
                                        />
                                        <span className="form-hint">
                                            Deixe vazio para permitir todos
                                        </span>
                                    </div>
                                )}

                                <div className="form-group">
                                    <label>
                                        Mínimo de Caracteres Únicos (diferentes)
                                    </label>
                                    <input
                                        type="number"
                                        min="0"
                                        max="64"
                                        value={editingPolicy.min_unique_chars}
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                min_unique_chars:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        Evita senhas como "aaaaaa1234" (0 =
                                        desabilitado)
                                    </span>
                                </div>
                            </div>

                            {/* Expiration and History */}
                            <div className="form-section">
                                <h4 className="section-title">
                                    📅 Expiração e Histórico
                                </h4>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Expiração da Senha (dias)</label>
                                        <input
                                            type="number"
                                            min="0"
                                            max="365"
                                            value={editingPolicy.max_age_days}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    max_age_days:
                                                        e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            0 = nunca expira (Recomendado: 90
                                            dias para roles sensíveis)
                                        </span>
                                    </div>

                                    <div className="form-group">
                                        <label>
                                            Histórico de Senhas (não reutilizar)
                                        </label>
                                        <input
                                            type="number"
                                            min="0"
                                            max="24"
                                            value={editingPolicy.history_count}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    history_count:
                                                        e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            0 = sem verificação (Recomendado: 5)
                                        </span>
                                    </div>
                                </div>

                                <div className="form-group">
                                    <label>
                                        Intervalo Mínimo entre Mudanças (horas)
                                    </label>
                                    <input
                                        type="number"
                                        min="0"
                                        max="720"
                                        value={editingPolicy.min_age_hours}
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                min_age_hours: e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        Previne mudanças rápidas maliciosas (0 =
                                        sem limite)
                                    </span>
                                </div>
                            </div>

                            {/* Security Checks */}
                            <div className="form-section">
                                <h4 className="section-title">
                                    🛡️ Verificações de Segurança
                                </h4>

                                <div className="checkboxes-grid">
                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.no_username_in_password
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    no_username_in_password:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>
                                            Bloquear nome de usuário na senha
                                        </span>
                                    </label>

                                    <label className="checkbox-label">
                                        <input
                                            type="checkbox"
                                            checked={
                                                editingPolicy.no_common_passwords
                                            }
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    no_common_passwords:
                                                        e.target.checked,
                                                })
                                            }
                                        />
                                        <span>
                                            Bloquear senhas comuns (ex: 123456,
                                            password)
                                        </span>
                                    </label>
                                </div>
                            </div>

                            {/* Description */}
                            <div className="form-section">
                                <h4 className="section-title">📝 Descrição</h4>

                                <div className="form-group">
                                    <textarea
                                        value={editingPolicy.description}
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                description: e.target.value,
                                            })
                                        }
                                        placeholder="Descrição opcional da política..."
                                        rows="2"
                                    />
                                </div>
                            </div>

                            {/* Info Box */}
                            <div className="info-box">
                                <div className="info-icon">ℹ️</div>
                                <div className="info-content">
                                    <strong>Recomendações de Segurança:</strong>
                                    <ul>
                                        <li>
                                            <strong>Root/Admin:</strong> Mínimo
                                            16-24 chars, expiração 90 dias,
                                            histórico 5 senhas
                                        </li>
                                        <li>
                                            <strong>User:</strong> Mínimo 12
                                            chars, expiração 180-365 dias
                                        </li>
                                        <li>
                                            <strong>Viewer:</strong> Mínimo 8
                                            chars, sem expiração obrigatória
                                        </li>
                                        <li>
                                            Sempre ative verificação de senhas
                                            comuns e username
                                        </li>
                                    </ul>
                                </div>
                            </div>

                            {/* Preview Box */}
                            <div className="preview-box">
                                <div className="preview-title">
                                    📊 Preview da Política
                                </div>
                                <div className="preview-content">
                                    <div className="preview-row">
                                        <div className="preview-item">
                                            <strong>Entropia estimada:</strong>
                                            <span className="preview-value">
                                                {calculatePasswordScore(
                                                    editingPolicy,
                                                )}{" "}
                                                bits
                                            </span>
                                        </div>
                                        <div className="preview-item">
                                            <strong>Nível de força:</strong>
                                            <span
                                                className={`strength-badge ${getStrengthLevel(editingPolicy).class}`}
                                            >
                                                {
                                                    getStrengthLevel(
                                                        editingPolicy,
                                                    ).level
                                                }
                                            </span>
                                        </div>
                                    </div>
                                    <div className="preview-item full-width">
                                        <strong>
                                            Exemplo de senha válida:
                                        </strong>
                                        <code className="password-example">
                                            {editingPolicy.require_uppercase
                                                ? "A"
                                                : ""}
                                            {editingPolicy.require_lowercase
                                                ? "b"
                                                : ""}
                                            {editingPolicy.require_numbers
                                                ? "1"
                                                : ""}
                                            {editingPolicy.require_special
                                                ? "@"
                                                : ""}
                                            {"x".repeat(
                                                Math.max(
                                                    0,
                                                    parseInt(
                                                        editingPolicy.min_length ||
                                                            8,
                                                    ) - 4,
                                                ),
                                            )}
                                        </code>
                                    </div>
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
                                disabled={saving}
                            >
                                Cancelar
                            </button>
                            <button
                                className="button-save"
                                onClick={handleSave}
                                disabled={saving}
                            >
                                {saving ? "Salvando..." : "💾 Salvar Política"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
