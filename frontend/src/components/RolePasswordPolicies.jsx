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
import "./RolePasswordPolicies.css";

export default function RolePasswordPolicies({ token, apiUrl }) {
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
    };

    const handleEdit = (policy) => {
        setEditingPolicy({
            role_id: policy.role_id,
            role_name: policy.role_name,
            min_length: policy.min_length,
            require_uppercase: policy.require_uppercase,
            require_lowercase: policy.require_lowercase,
            require_numbers: policy.require_numbers,
            require_special: policy.require_special,
            max_age: policy.max_age || "",
            prevent_reuse: policy.prevent_reuse || "",
            min_change_interval: policy.min_change_interval || "",
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
                editingPolicy.min_length < 8 ||
                editingPolicy.min_length > 128
            ) {
                setError(
                    "Tamanho mínimo de senha deve estar entre 8 e 128 caracteres",
                );
                return;
            }

            const payload = {
                min_length: parseInt(editingPolicy.min_length),
                require_uppercase: editingPolicy.require_uppercase,
                require_lowercase: editingPolicy.require_lowercase,
                require_numbers: editingPolicy.require_numbers,
                require_special: editingPolicy.require_special,
                max_age:
                    editingPolicy.max_age !== ""
                        ? parseInt(editingPolicy.max_age)
                        : null,
                prevent_reuse:
                    editingPolicy.prevent_reuse !== ""
                        ? parseInt(editingPolicy.prevent_reuse)
                        : null,
                min_change_interval:
                    editingPolicy.min_change_interval !== ""
                        ? parseInt(editingPolicy.min_change_interval)
                        : null,
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

    const getStrengthLevel = (policy) => {
        let score = 0;

        // Length
        if (policy.min_length >= 20) score += 3;
        else if (policy.min_length >= 16) score += 2;
        else if (policy.min_length >= 12) score += 1;

        // Requirements
        if (policy.require_uppercase) score += 1;
        if (policy.require_lowercase) score += 1;
        if (policy.require_numbers) score += 1;
        if (policy.require_special) score += 1;

        // Advanced features
        if (policy.max_age && policy.max_age <= 90) score += 2;
        if (policy.prevent_reuse && policy.prevent_reuse >= 5) score += 1;
        if (policy.min_change_interval) score += 1;

        if (score >= 10)
            return { level: "Muito Forte", class: "strength-very-high" };
        if (score >= 7) return { level: "Forte", class: "strength-high" };
        if (score >= 5) return { level: "Média", class: "strength-medium" };
        return { level: "Básica", class: "strength-low" };
    };

    const calculatePasswordScore = (policy) => {
        let complexity = 0;

        // Character set size
        let charsetSize = 0;
        if (policy.require_lowercase) charsetSize += 26;
        if (policy.require_uppercase) charsetSize += 26;
        if (policy.require_numbers) charsetSize += 10;
        if (policy.require_special) charsetSize += 32;

        if (charsetSize > 0) {
            // Entropy calculation: log2(charset^length)
            const entropy =
                policy.min_length * Math.log2(charsetSize);
            complexity = Math.round(entropy);
        }

        return complexity;
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
                        Configure requisitos de senha e regras de segurança para
                        cada nível de usuário
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
                    const strength = getStrengthLevel(policy);
                    const score = calculatePasswordScore(policy);
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
                                        className={`strength-badge ${strength.class}`}
                                    >
                                        🛡️ {strength.level}
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
                                <div className="policy-metric">
                                    <div className="metric-header">
                                        <span className="metric-label">
                                            Tamanho Mínimo
                                        </span>
                                        <span className="metric-value-large">
                                            {policy.min_length}
                                        </span>
                                    </div>
                                    <div className="metric-subtitle">
                                        caracteres
                                    </div>
                                </div>

                                <div className="policy-metric">
                                    <div className="metric-header">
                                        <span className="metric-label">
                                            Entropia
                                        </span>
                                        <span className="metric-value-large">
                                            {score}
                                        </span>
                                    </div>
                                    <div className="metric-subtitle">
                                        bits de complexidade
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
                                    <div className="advanced-item">
                                        <span className="adv-icon">📅</span>
                                        <span className="adv-text">
                                            Expiração:{" "}
                                            {policy.max_age
                                                ? `${policy.max_age} dias`
                                                : "Nunca"}
                                        </span>
                                    </div>
                                    <div className="advanced-item">
                                        <span className="adv-icon">🔄</span>
                                        <span className="adv-text">
                                            Prevenir reuso:{" "}
                                            {policy.prevent_reuse
                                                ? `${policy.prevent_reuse} senhas`
                                                : "Não"}
                                        </span>
                                    </div>
                                    <div className="advanced-item">
                                        <span className="adv-icon">⏱️</span>
                                        <span className="adv-text">
                                            Intervalo mínimo:{" "}
                                            {policy.min_change_interval
                                                ? `${policy.min_change_interval}h`
                                                : "Sem limite"}
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
                                Editar Política de Senha -{" "}
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
                            <div className="form-section">
                                <h4 className="section-title">
                                    Requisitos Básicos
                                </h4>

                                <div className="form-group">
                                    <label>
                                        Tamanho Mínimo (caracteres)
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
                                        <span>
                                            Exigir Especiais (!@#$%...)
                                        </span>
                                    </label>
                                </div>
                            </div>

                            <div className="form-section">
                                <h4 className="section-title">
                                    Regras Avançadas
                                </h4>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Expiração da Senha (dias)</label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="365"
                                            placeholder="Nunca expira"
                                            value={editingPolicy.max_age}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    max_age: e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            {editingPolicy.max_age
                                                ? `Senha expira após ${editingPolicy.max_age} dias`
                                                : "Deixe vazio para nunca expirar"}
                                        </span>
                                    </div>

                                    <div className="form-group">
                                        <label>
                                            Prevenir Reuso (últimas N senhas)
                                        </label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="24"
                                            placeholder="Sem prevenção"
                                            value={editingPolicy.prevent_reuse}
                                            onChange={(e) =>
                                                setEditingPolicy({
                                                    ...editingPolicy,
                                                    prevent_reuse:
                                                        e.target.value,
                                                })
                                            }
                                        />
                                        <span className="form-hint">
                                            {editingPolicy.prevent_reuse
                                                ? `Não pode reusar as últimas ${editingPolicy.prevent_reuse} senhas`
                                                : "Deixe vazio para permitir reuso"}
                                        </span>
                                    </div>
                                </div>

                                <div className="form-group">
                                    <label>
                                        Intervalo Mínimo entre Mudanças (horas)
                                    </label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="168"
                                        placeholder="Sem limite"
                                        value={
                                            editingPolicy.min_change_interval
                                        }
                                        onChange={(e) =>
                                            setEditingPolicy({
                                                ...editingPolicy,
                                                min_change_interval:
                                                    e.target.value,
                                            })
                                        }
                                    />
                                    <span className="form-hint">
                                        {editingPolicy.min_change_interval
                                            ? `Usuário deve aguardar ${editingPolicy.min_change_interval}h para mudar senha novamente`
                                            : "Deixe vazio para sem limite"}
                                    </span>
                                </div>
                            </div>

                            <div className="info-box">
                                <div className="info-icon">ℹ️</div>
                                <div className="info-content">
                                    <strong>
                                        Recomendações de Segurança:
                                    </strong>
                                    <ul>
                                        <li>
                                            Senhas mais longas são
                                            exponencialmente mais seguras
                                        </li>
                                        <li>
                                            Exija todos os tipos de caracteres
                                            para maior entropia
                                        </li>
                                        <li>
                                            Considere expiração de 90 dias para
                                            roles sensíveis
                                        </li>
                                        <li>
                                            Previna reuso de pelo menos 5 senhas
                                            anteriores
                                        </li>
                                        <li>
                                            Intervalo mínimo previne mudanças
                                            rápidas maliciosas
                                        </li>
                                    </ul>
                                </div>
                            </div>

                            <div className="preview-box">
                                <div className="preview-title">
                                    📊 Preview da Política
                                </div>
                                <div className="preview-content">
                                    <div className="preview-item">
                                        <strong>Exemplo de senha válida:</strong>
                                        <code>
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
                                                        editingPolicy.min_length,
                                                    ) - 4,
                                                ),
                                            )}
                                        </code>
                                    </div>
                                    <div className="preview-item">
                                        <strong>Entropia estimada:</strong>
                                        <span>
                                            {" "}
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
                                                getStrengthLevel(editingPolicy)
                                                    .level
                                            }
                                        </span>
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
