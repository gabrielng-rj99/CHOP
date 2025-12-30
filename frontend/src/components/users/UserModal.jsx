/*
 * This file is part of Client Hub Open Project.
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
import "./UserModal.css";

export default function UserModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    onSubmit,
    onClose,
    error,
    currentUserRole,
    apiUrl,
    token,
}) {
    const [passwordLength, setPasswordLength] = useState(42);
    const [showPassword, setShowPassword] = useState(false);
    const [passwordCopied, setPasswordCopied] = useState(false);
    const [isPasswordFocused, setIsPasswordFocused] = useState(false);

    // Roles state
    const [roles, setRoles] = useState([]);
    const [rolesLoading, setRolesLoading] = useState(true);
    const [rolesError, setRolesError] = useState("");

    // Custom role modal
    const [showCustomRoleModal, setShowCustomRoleModal] = useState(false);
    const [customRoleData, setCustomRoleData] = useState({
        display_name: "",
        description: "",
        permissions: {},
    });
    const [permissions, setPermissions] = useState([]);
    const [permissionsByCategory, setPermissionsByCategory] = useState({});

    // Password policy for selected role
    const [passwordPolicy, setPasswordPolicy] = useState(null);

    const isRoot = currentUserRole === "root";

    // Load roles when modal opens
    useEffect(() => {
        if (showModal && apiUrl && token) {
            loadRoles();
        }
    }, [showModal, apiUrl, token]);

    // Load password policy when role changes
    useEffect(() => {
        if (formData.role_id && apiUrl && token) {
            loadPasswordPolicy(formData.role_id);
        }
    }, [formData.role_id, apiUrl, token]);

    const loadRoles = async () => {
        setRolesLoading(true);
        setRolesError("");
        try {
            const response = await fetch(`${apiUrl}/roles`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                // Filter roles based on current user's priority
                // Admin can only assign roles with lower priority than their own
                const filteredRoles = data
                    .map((r) => r.role || r)
                    .filter((role) => {
                        if (isRoot) return true;
                        // Non-root users can only assign roles up to their own level
                        // Assuming admin has priority 50, they can assign user (10), viewer (1), etc.
                        if (currentUserRole === "admin") {
                            return role.priority < 50;
                        }
                        return false;
                    });
                setRoles(filteredRoles);

                // If no role selected yet, select the first available
                if (!formData.role_id && filteredRoles.length > 0) {
                    const defaultRole =
                        filteredRoles.find((r) => r.name === "user") ||
                        filteredRoles[0];
                    setFormData({
                        ...formData,
                        role: defaultRole.name,
                        role_id: defaultRole.id,
                    });
                }
            } else {
                // Fallback to hardcoded roles if API fails
                setRolesError(
                    "Não foi possível carregar papéis. Usando padrão.",
                );
                setRoles([
                    {
                        id: "user",
                        name: "user",
                        display_name: "Usuário",
                        priority: 10,
                    },
                    {
                        id: "admin",
                        name: "admin",
                        display_name: "Administrador",
                        priority: 50,
                    },
                    {
                        id: "root",
                        name: "root",
                        display_name: "Super Administrador",
                        priority: 100,
                    },
                ]);
            }
        } catch (err) {
            setRolesError("Erro ao carregar papéis: " + err.message);
            // Fallback
            setRoles([
                {
                    id: "user",
                    name: "user",
                    display_name: "Usuário",
                    priority: 10,
                },
                {
                    id: "admin",
                    name: "admin",
                    display_name: "Administrador",
                    priority: 50,
                },
                {
                    id: "root",
                    name: "root",
                    display_name: "Super Administrador",
                    priority: 100,
                },
            ]);
        } finally {
            setRolesLoading(false);
        }
    };

    const loadPasswordPolicy = async (roleId) => {
        try {
            const response = await fetch(
                `${apiUrl}/roles/${roleId}/password-policy`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                },
            );
            if (response.ok) {
                const data = await response.json();
                setPasswordPolicy(data);
            } else {
                setPasswordPolicy(null);
            }
        } catch (err) {
            setPasswordPolicy(null);
        }
    };

    const loadPermissions = async () => {
        try {
            const response = await fetch(`${apiUrl}/permissions`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });
            if (response.ok) {
                const data = await response.json();
                // Null check para evitar erro quando data é null ou undefined
                const permissionsData = data || [];
                setPermissions(permissionsData);

                // Group by category
                const byCategory = {};
                permissionsData.forEach((perm) => {
                    const cat = perm.category || "Geral";
                    if (!byCategory[cat]) byCategory[cat] = [];
                    byCategory[cat].push(perm);
                });
                setPermissionsByCategory(byCategory);
            }
        } catch (err) {
            console.error("Error loading permissions:", err);
        }
    };

    const handleOpenCustomRoleModal = () => {
        setCustomRoleData({
            display_name: formData.display_name
                ? `Papel de ${formData.display_name}`
                : "Papel Personalizado",
            description: `Papel personalizado criado para usuário específico`,
            permissions: {},
        });
        loadPermissions();
        setShowCustomRoleModal(true);
    };

    const handleCreateCustomRole = async () => {
        try {
            // Create the custom role
            const roleResponse = await fetch(`${apiUrl}/roles`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                    name: `custom_${Date.now()}`,
                    display_name: customRoleData.display_name,
                    description: customRoleData.description,
                    priority: 5, // Low priority for custom roles
                    is_single_user: true, // Mark as single-user role
                }),
            });

            if (!roleResponse.ok) {
                throw new Error("Falha ao criar papel personalizado");
            }

            const newRole = await roleResponse.json();

            // Set permissions for the new role
            const enabledPermissions = Object.entries(
                customRoleData.permissions,
            )
                .filter(([_, enabled]) => enabled)
                .map(([permId]) => permId);

            if (enabledPermissions.length > 0) {
                await fetch(`${apiUrl}/roles/${newRole.id}/permissions`, {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`,
                    },
                    body: JSON.stringify({
                        permission_ids: enabledPermissions,
                    }),
                });
            }

            // Update form with new role
            setFormData({
                ...formData,
                role: newRole.name,
                role_id: newRole.id,
            });

            // Refresh roles list
            await loadRoles();

            setShowCustomRoleModal(false);
        } catch (err) {
            alert("Erro ao criar papel personalizado: " + err.message);
        }
    };

    const handlePermissionToggle = (permId) => {
        setCustomRoleData({
            ...customRoleData,
            permissions: {
                ...customRoleData.permissions,
                [permId]: !customRoleData.permissions[permId],
            },
        });
    };

    const handleSelectAllCategory = (category, perms) => {
        const allSelected = perms.every(
            (p) => customRoleData.permissions[p.id],
        );
        const newPerms = { ...customRoleData.permissions };
        perms.forEach((p) => {
            newPerms[p.id] = !allSelected;
        });
        setCustomRoleData({
            ...customRoleData,
            permissions: newPerms,
        });
    };

    if (!showModal) return null;

    const generateRandomPassword = (customLength) => {
        const length = customLength ?? passwordLength;
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const numbers = "0123456789";
        const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        const allChars = lowercase + uppercase + numbers + symbols;

        let password = "";

        // Garantir pelo menos um de cada tipo
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        // Preencher o resto
        for (let i = password.length; i < length; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        // Embaralhar a senha
        password = password
            .split("")
            .sort(() => Math.random() - 0.5)
            .join("");

        setFormData({
            ...formData,
            password: password,
        });

        return password;
    };

    const copyPasswordToClipboard = () => {
        if (formData.password) {
            navigator.clipboard.writeText(formData.password);
            setPasswordCopied(true);
            setTimeout(() => setPasswordCopied(false), 1500);
        }
    };

    const handleRoleChange = (e) => {
        const selectedRoleId = e.target.value;

        if (selectedRoleId === "custom") {
            handleOpenCustomRoleModal();
            return;
        }

        const selectedRole = roles.find((r) => r.id === selectedRoleId);
        if (selectedRole) {
            setFormData({
                ...formData,
                role: selectedRole.name,
                role_id: selectedRole.id,
            });
        }
    };

    const getRoleBadgeClass = (roleName) => {
        switch (roleName) {
            case "root":
                return "role-badge-root";
            case "admin":
                return "role-badge-admin";
            case "viewer":
                return "role-badge-viewer";
            default:
                return "role-badge-user";
        }
    };

    const getPriorityLabel = (priority) => {
        if (priority >= 100) return "🔴 Crítico";
        if (priority >= 50) return "🟠 Alto";
        if (priority >= 10) return "🟡 Médio";
        return "🟢 Baixo";
    };

    const getActionIcon = (action) => {
        const icons = {
            create: "➕",
            read: "👁️",
            update: "✏️",
            delete: "🗑️",
            archive: "📦",
            export: "📤",
            block: "🚫",
            manage: "⚙️",
            manage_roles: "👥",
            manage_global: "🌐",
            manage_permissions: "🔐",
            manage_security: "🛡️",
            manage_branding: "🎨",
            configure: "⚙️",
        };
        return icons[action] || "📋";
    };

    const getCategoryIcon = (category) => {
        const icons = {
            Entidades: "🏢",
            "Sub-entidades": "🏠",
            Acordos: "📄",
            Categorias: "🏷️",
            Usuários: "👤",
            Auditoria: "📋",
            Sistema: "⚙️",
            Aparência: "🎨",
            Dashboard: "📊",
            Geral: "📂",
        };
        return icons[category] || "📂";
    };

    return (
        <>
            <div className="user-modal-overlay" onClick={onClose}>
                <div
                    onClick={(e) => e.stopPropagation()}
                    className="user-modal-content"
                >
                    <h2 className="user-modal-title">
                        {modalMode === "create"
                            ? "Novo Usuário"
                            : "Editar Usuário"}
                    </h2>

                    <form onSubmit={onSubmit}>
                        {/* Username & Display Name Side by Side */}
                        <div
                            className="user-modal-form-row"
                            style={{ display: "flex", gap: "16px" }}
                        >
                            <div style={{ flex: 1 }}>
                                <label className="user-modal-label">
                                    Nome de Usuário *
                                </label>
                                <input
                                    type="text"
                                    value={formData.username}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            username: e.target.value,
                                        })
                                    }
                                    required
                                    disabled={modalMode === "edit" && !isRoot}
                                    className="user-modal-input"
                                    style={{ width: "100%" }}
                                />
                                {modalMode === "edit" && !isRoot && (
                                    <small className="user-modal-hint">
                                        Apenas usuários root podem alterar
                                        username
                                    </small>
                                )}
                            </div>
                            <div style={{ flex: 1 }}>
                                <label className="user-modal-label">
                                    Nome de Exibição *
                                </label>
                                <input
                                    type="text"
                                    value={formData.display_name}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            display_name: e.target.value,
                                        })
                                    }
                                    required
                                    className="user-modal-input"
                                    style={{ width: "100%" }}
                                />
                            </div>
                        </div>

                        {/* Password */}
                        <div className="user-modal-form-group">
                            <label className="user-modal-label">
                                Senha{" "}
                                {modalMode === "create"
                                    ? "*"
                                    : "(deixe em branco para manter)"}
                            </label>
                            <div
                                className="user-modal-password-group"
                                style={{
                                    display: "flex",
                                    alignItems: "center",
                                    width: "100%",
                                    gap: "8px",
                                }}
                            >
                                <input
                                    type={showPassword ? "text" : "password"}
                                    value={formData.password}
                                    onChange={(e) => {
                                        let val = e.target.value.replace(
                                            /\n/g,
                                            "",
                                        );
                                        if (val.length > 128)
                                            val = val.slice(0, 128);
                                        setFormData({
                                            ...formData,
                                            password: val,
                                        });
                                    }}
                                    maxLength={128}
                                    className="user-modal-input user-modal-password-input"
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <button
                                    type="button"
                                    onClick={() =>
                                        setShowPassword(!showPassword)
                                    }
                                    className="user-modal-password-toggle"
                                    title={
                                        showPassword
                                            ? "Ocultar senha"
                                            : "Mostrar senha"
                                    }
                                >
                                    {showPassword ? "👁️" : "𓁹"}
                                </button>
                                <button
                                    type="button"
                                    onClick={copyPasswordToClipboard}
                                    className="user-modal-password-toggle user-modal-password-copy"
                                    title="Copiar senha"
                                >
                                    📋
                                </button>
                                {passwordCopied && (
                                    <span className="user-modal-password-copied">
                                        Senha copiada!
                                    </span>
                                )}
                            </div>

                            {/* Password Policy Info */}
                            {passwordPolicy && (
                                <div className="user-modal-password-policy">
                                    <small className="policy-title">
                                        📋 Requisitos de senha para este papel:
                                    </small>
                                    <ul className="policy-list">
                                        <li>
                                            Mínimo {passwordPolicy.min_length}{" "}
                                            caracteres
                                        </li>
                                        {passwordPolicy.require_uppercase && (
                                            <li>
                                                Pelo menos uma letra maiúscula
                                            </li>
                                        )}
                                        {passwordPolicy.require_lowercase && (
                                            <li>
                                                Pelo menos uma letra minúscula
                                            </li>
                                        )}
                                        {passwordPolicy.require_numbers && (
                                            <li>Pelo menos um número</li>
                                        )}
                                        {passwordPolicy.require_special && (
                                            <li>
                                                Pelo menos um caractere especial
                                            </li>
                                        )}
                                        {passwordPolicy.max_age_days > 0 && (
                                            <li>
                                                Expira a cada{" "}
                                                {passwordPolicy.max_age_days}{" "}
                                                dias
                                            </li>
                                        )}
                                    </ul>
                                </div>
                            )}

                            {/* Password Generator */}
                            <div className="user-modal-password-generator">
                                <div className="user-modal-password-generator-header">
                                    <label className="user-modal-label-small">
                                        Gerar Senha Automática
                                    </label>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            const newPassword =
                                                generateRandomPassword(
                                                    passwordLength,
                                                );
                                            setFormData({
                                                ...formData,
                                                password: newPassword,
                                            });
                                            setTimeout(() => {
                                                navigator.clipboard.writeText(
                                                    newPassword,
                                                );
                                                setPasswordCopied(true);
                                                setTimeout(
                                                    () =>
                                                        setPasswordCopied(
                                                            false,
                                                        ),
                                                    1500,
                                                );
                                            }, 100);
                                        }}
                                        className="user-modal-generate-button"
                                    >
                                        🎲 Gerar e Copiar
                                    </button>
                                </div>
                                <div className="user-modal-password-slider">
                                    <input
                                        type="range"
                                        min={passwordPolicy?.min_length || 24}
                                        max="128"
                                        value={passwordLength}
                                        onChange={(e) => {
                                            const newLength = parseInt(
                                                e.target.value,
                                            );
                                            setPasswordLength(newLength);
                                            generateRandomPassword(newLength);
                                        }}
                                        className="user-modal-slider"
                                    />
                                    <span className="user-modal-slider-value">
                                        {passwordLength} caracteres
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Role Selection */}
                        <div className="user-modal-form-group">
                            <label className="user-modal-label">Função *</label>

                            {rolesLoading ? (
                                <div className="user-modal-loading">
                                    Carregando papéis...
                                </div>
                            ) : (
                                <>
                                    {rolesError && (
                                        <small className="user-modal-hint user-modal-hint-warning">
                                            ⚠️ {rolesError}
                                        </small>
                                    )}

                                    <select
                                        value={formData.role_id || ""}
                                        onChange={handleRoleChange}
                                        required
                                        className="user-modal-select"
                                        data-role={formData.role}
                                    >
                                        <option value="" disabled>
                                            Selecione um papel...
                                        </option>

                                        {roles.map((role) => (
                                            <option
                                                key={role.id}
                                                value={role.id}
                                                className={`user-modal-option ${getRoleBadgeClass(role.name)}`}
                                            >
                                                {role.display_name} ({role.name}
                                                ){role.is_single_user && " 👤"}
                                            </option>
                                        ))}

                                        {/* Custom role option - only for root */}
                                        {isRoot && (
                                            <option
                                                value="custom"
                                                className="user-modal-option user-modal-option-custom"
                                            >
                                                ✨ Criar Papel Personalizado...
                                            </option>
                                        )}
                                    </select>

                                    {/* Selected role info */}
                                    {formData.role_id && (
                                        <div className="user-modal-role-info">
                                            {(() => {
                                                const selectedRole = roles.find(
                                                    (r) =>
                                                        r.id ===
                                                        formData.role_id,
                                                );
                                                if (!selectedRole) return null;
                                                return (
                                                    <>
                                                        <span className="role-priority">
                                                            {getPriorityLabel(
                                                                selectedRole.priority,
                                                            )}
                                                        </span>
                                                        {selectedRole.description && (
                                                            <p className="role-description">
                                                                {
                                                                    selectedRole.description
                                                                }
                                                            </p>
                                                        )}
                                                        {selectedRole.is_system && (
                                                            <span className="role-system-badge">
                                                                🔒 Papel de
                                                                sistema
                                                            </span>
                                                        )}
                                                        {selectedRole.is_single_user && (
                                                            <span className="role-single-badge">
                                                                👤 Papel único
                                                                (este usuário
                                                                apenas)
                                                            </span>
                                                        )}
                                                    </>
                                                );
                                            })()}
                                        </div>
                                    )}

                                    {/* Root only warning */}
                                    {isRoot && formData.role === "root" && (
                                        <div className="user-modal-root-warning">
                                            ⚠️ <strong>ROOT ONLY:</strong> Este
                                            papel tem acesso total ao sistema.
                                            Use com cuidado.
                                        </div>
                                    )}
                                </>
                            )}
                        </div>

                        {error && (
                            <div className="user-modal-error">{error}</div>
                        )}

                        <div className="user-modal-button-group">
                            <button
                                type="button"
                                onClick={onClose}
                                className="user-modal-button user-modal-button-cancel"
                            >
                                Cancelar
                            </button>
                            <button
                                type="submit"
                                className="user-modal-button user-modal-button-submit"
                            >
                                {modalMode === "create" ? "Criar" : "Salvar"}
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            {/* Custom Role Modal */}
            {showCustomRoleModal && (
                <div
                    className="user-modal-overlay custom-role-overlay"
                    onClick={() => setShowCustomRoleModal(false)}
                >
                    <div
                        onClick={(e) => e.stopPropagation()}
                        className="user-modal-content custom-role-modal"
                    >
                        <h2 className="user-modal-title">
                            ✨ Criar Papel Personalizado
                        </h2>

                        <div className="custom-role-notice">
                            <span className="notice-badge">ROOT ONLY</span>
                            <p>
                                Este papel será criado especificamente para este
                                usuário. Você pode selecionar as permissões
                                individualmente.
                            </p>
                        </div>

                        <div className="user-modal-form-group">
                            <label className="user-modal-label">
                                Nome do Papel *
                            </label>
                            <input
                                type="text"
                                value={customRoleData.display_name}
                                onChange={(e) =>
                                    setCustomRoleData({
                                        ...customRoleData,
                                        display_name: e.target.value,
                                    })
                                }
                                required
                                className="user-modal-input"
                                placeholder="Ex: Operador Financeiro Júnior"
                            />
                        </div>

                        <div className="user-modal-form-group">
                            <label className="user-modal-label">
                                Descrição
                            </label>
                            <textarea
                                value={customRoleData.description}
                                onChange={(e) =>
                                    setCustomRoleData({
                                        ...customRoleData,
                                        description: e.target.value,
                                    })
                                }
                                className="user-modal-input user-modal-textarea"
                                placeholder="Descreva as responsabilidades deste papel..."
                                rows={2}
                            />
                        </div>

                        <div className="custom-role-permissions">
                            <label className="user-modal-label">
                                Permissões
                            </label>

                            <div className="permissions-grid-custom">
                                {Object.entries(permissionsByCategory).map(
                                    ([category, perms]) => (
                                        <div
                                            key={category}
                                            className="permission-category"
                                        >
                                            <div className="category-header">
                                                <span className="category-icon">
                                                    {getCategoryIcon(category)}
                                                </span>
                                                <span className="category-name">
                                                    {category}
                                                </span>
                                                <button
                                                    type="button"
                                                    className="select-all-btn"
                                                    onClick={() =>
                                                        handleSelectAllCategory(
                                                            category,
                                                            perms,
                                                        )
                                                    }
                                                >
                                                    {perms.every(
                                                        (p) =>
                                                            customRoleData
                                                                .permissions[
                                                                p.id
                                                            ],
                                                    )
                                                        ? "Desmarcar"
                                                        : "Selecionar"}{" "}
                                                    tudo
                                                </button>
                                            </div>

                                            <div className="permission-list">
                                                {perms.map((perm) => (
                                                    <label
                                                        key={perm.id}
                                                        className="permission-item"
                                                    >
                                                        <input
                                                            type="checkbox"
                                                            checked={
                                                                customRoleData
                                                                    .permissions[
                                                                    perm.id
                                                                ] || false
                                                            }
                                                            onChange={() =>
                                                                handlePermissionToggle(
                                                                    perm.id,
                                                                )
                                                            }
                                                        />
                                                        <span className="perm-icon">
                                                            {getActionIcon(
                                                                perm.action,
                                                            )}
                                                        </span>
                                                        <span className="perm-name">
                                                            {perm.display_name}
                                                        </span>
                                                    </label>
                                                ))}
                                            </div>
                                        </div>
                                    ),
                                )}
                            </div>
                        </div>

                        <div className="user-modal-button-group">
                            <button
                                type="button"
                                onClick={() => setShowCustomRoleModal(false)}
                                className="user-modal-button user-modal-button-cancel"
                            >
                                Cancelar
                            </button>
                            <button
                                type="button"
                                onClick={handleCreateCustomRole}
                                className="user-modal-button user-modal-button-submit"
                                disabled={!customRoleData.display_name}
                            >
                                Criar Papel
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
