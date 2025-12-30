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
import "./RolesPermissions.css";

export default function RolesPermissions({ token, apiUrl }) {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");

    // Data state
    const [roles, setRoles] = useState([]);
    const [permissions, setPermissions] = useState([]);
    const [permissionsByCategory, setPermissionsByCategory] = useState({});
    const [selectedRole, setSelectedRole] = useState(null);
    const [rolePermissions, setRolePermissions] = useState({});

    // Modal state
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showPermissionsModal, setShowPermissionsModal] = useState(false);
    const [activeCategory, setActiveCategory] = useState(null);
    const [newRole, setNewRole] = useState({
        name: "",
        display_name: "",
        description: "",
        priority: 10,
        priority_level: "medium", // low, medium, high
    });

    // Priority level mappings
    const priorityLevels = [
        {
            value: "low",
            label: "🟢 Baixo (Visualizador)",
            priority: 5,
            description: "Acesso limitado, geralmente somente leitura",
        },
        {
            value: "medium",
            label: "🟡 Médio (Operador)",
            priority: 25,
            description: "Acesso padrão para operações do dia-a-dia",
        },
        {
            value: "high",
            label: "🟠 Alto (Administrador)",
            priority: 50,
            description: "Acesso amplo, gerencia usuários e configurações",
        },
    ];

    const getPriorityLevel = (priority) => {
        if (priority >= 50) return "high";
        if (priority >= 10) return "medium";
        return "low";
    };

    const getPriorityFromLevel = (level) => {
        const found = priorityLevels.find((p) => p.value === level);
        return found ? found.priority : 10;
    };

    const getPriorityLabel = (priority) => {
        if (priority >= 100) return "🔴 Crítico (Sistema)";
        if (priority >= 50) return "🟠 Alto";
        if (priority >= 10) return "🟡 Médio";
        return "🟢 Baixo";
    };

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        try {
            setLoading(true);

            // Load roles with permissions
            const rolesResponse = await fetch(
                `${apiUrl}/roles?include_permissions=true`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                },
            );

            if (rolesResponse.ok) {
                const rolesData = await rolesResponse.json();
                setRoles(rolesData || []);

                // Build role permissions map
                const permMap = {};
                (rolesData || []).forEach((rwp) => {
                    permMap[rwp.role.id] = {};
                    (rwp.permissions || []).forEach((p) => {
                        permMap[rwp.role.id][p.id] = true;
                    });
                });
                setRolePermissions(permMap);

                // Select first role by default
                if (rolesData && rolesData.length > 0) {
                    setSelectedRole(rolesData[0].role);
                }
            }

            // Load all permissions
            const permsResponse = await fetch(
                `${apiUrl}/permissions?group_by=category`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                },
            );

            if (permsResponse.ok) {
                const permsData = await permsResponse.json();
                setPermissionsByCategory(permsData || {});

                // Flatten permissions for easy access
                const allPerms = [];
                Object.values(permsData || {}).forEach((perms) => {
                    allPerms.push(...perms);
                });
                setPermissions(allPerms);
            }
        } catch (err) {
            console.error("Error loading roles/permissions:", err);
            setError("Erro ao carregar dados de papéis e permissões");
        } finally {
            setLoading(false);
        }
    };

    const handleCreateRole = async () => {
        if (!newRole.name || !newRole.display_name) {
            setError("Nome e nome de exibição são obrigatórios");
            return;
        }

        setSaving(true);
        setError("");

        try {
            // Garantir que priority é um número inteiro
            const roleData = {
                name: newRole.name,
                display_name: newRole.display_name,
                description: newRole.description || null,
                priority: parseInt(newRole.priority, 10) || 10,
            };

            const response = await fetch(`${apiUrl}/roles`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(roleData),
            });

            if (response.ok) {
                setMessage("Papel criado com sucesso!");
                setShowCreateModal(false);
                setNewRole({
                    name: "",
                    display_name: "",
                    description: "",
                    priority: 5,
                });
                loadData();
            } else {
                const data = await response.json();
                setError(data.error || "Erro ao criar papel");
            }
        } catch (err) {
            console.error("Error creating role:", err);
            setError("Erro ao criar papel. Tente novamente.");
        } finally {
            setSaving(false);
        }
    };

    const handleUpdateRole = async () => {
        if (!selectedRole) return;

        setSaving(true);
        setError("");

        try {
            const response = await fetch(`${apiUrl}/roles/${selectedRole.id}`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                    display_name: selectedRole.display_name,
                    description: selectedRole.description,
                    priority: selectedRole.priority,
                }),
            });

            if (response.ok) {
                setMessage("Papel atualizado com sucesso!");
                setShowEditModal(false);
                loadData();
            } else {
                const data = await response.json();
                setError(data.error || "Erro ao atualizar papel");
            }
        } catch (err) {
            console.error("Error updating role:", err);
            setError("Erro ao atualizar papel. Tente novamente.");
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteRole = async (roleId) => {
        if (
            !window.confirm(
                "Tem certeza que deseja deletar este papel? Esta ação não pode ser desfeita.",
            )
        ) {
            return;
        }

        try {
            const response = await fetch(`${apiUrl}/roles/${roleId}`, {
                method: "DELETE",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (response.ok) {
                setMessage("Papel deletado com sucesso!");
                loadData();
            } else {
                const data = await response.json();
                setError(data.error || "Erro ao deletar papel");
            }
        } catch (err) {
            console.error("Error deleting role:", err);
            setError("Erro ao deletar papel. Tente novamente.");
        }
    };

    const handlePermissionToggle = async (permissionId) => {
        if (!selectedRole) {
            console.warn("No role selected");
            return;
        }

        // Root role permissions cannot be modified
        if (selectedRole.name === "root") {
            setError("Permissões do papel root não podem ser modificadas");
            return;
        }

        // Clear any previous messages
        setError("");
        setMessage("");

        const currentPerms = rolePermissions[selectedRole.id] || {};
        const isEnabled = currentPerms[permissionId];

        console.log(
            `Toggling permission ${permissionId} for role ${selectedRole.id}: ${isEnabled} -> ${!isEnabled}`,
        );

        // Optimistically update UI
        const newPerms = {
            ...currentPerms,
            [permissionId]: !isEnabled,
        };
        setRolePermissions((prev) => ({
            ...prev,
            [selectedRole.id]: newPerms,
        }));

        // Get all permission IDs that should be enabled
        const enabledPermIds = Object.entries(newPerms)
            .filter(([_, enabled]) => enabled)
            .map(([id, _]) => id);

        console.log(`Sending ${enabledPermIds.length} permissions to API`);

        try {
            const response = await fetch(
                `${apiUrl}/roles/${selectedRole.id}/permissions`,
                {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`,
                    },
                    body: JSON.stringify({
                        permission_ids: enabledPermIds,
                    }),
                },
            );

            if (!response.ok) {
                // Revert on error
                setRolePermissions((prev) => ({
                    ...prev,
                    [selectedRole.id]: currentPerms,
                }));
                const data = await response.json();
                console.error("API error:", data);
                setError(data.error || "Erro ao atualizar permissões");
            } else {
                console.log("Permission updated successfully");
            }
        } catch (err) {
            // Revert on error
            setRolePermissions((prev) => ({
                ...prev,
                [selectedRole.id]: currentPerms,
            }));
            console.error("Error updating permissions:", err);
            setError("Erro ao atualizar permissões. Tente novamente.");
        }
    };

    const handleSelectAllCategory = async (categoryPerms, enable) => {
        if (!selectedRole || selectedRole.name === "root") return;

        const currentPerms = { ...(rolePermissions[selectedRole.id] || {}) };

        categoryPerms.forEach((perm) => {
            currentPerms[perm.id] = enable;
        });

        setRolePermissions((prev) => ({
            ...prev,
            [selectedRole.id]: currentPerms,
        }));

        const enabledPermIds = Object.entries(currentPerms)
            .filter(([_, enabled]) => enabled)
            .map(([id, _]) => id);

        try {
            const response = await fetch(
                `${apiUrl}/roles/${selectedRole.id}/permissions`,
                {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`,
                    },
                    body: JSON.stringify({
                        permission_ids: enabledPermIds,
                    }),
                },
            );

            if (!response.ok) {
                loadData(); // Reload on error
                const data = await response.json();
                setError(data.error || "Erro ao atualizar permissões");
            }
        } catch (err) {
            loadData();
            console.error("Error updating permissions:", err);
        }
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
        };
        return icons[action] || "•";
    };

    const getCategoryIcon = (category) => {
        const icons = {
            Entidades: "👤",
            "Sub-entidades": "👥",
            Acordos: "📝",
            Categorias: "📁",
            Usuários: "👤",
            Auditoria: "📋",
            Sistema: "⚙️",
            Aparência: "🎨",
            Dashboard: "📊",
        };
        return icons[category] || "📂";
    };

    if (loading) {
        return (
            <div className="roles-loading">
                <div className="spinner"></div>
                <p>Carregando papéis e permissões...</p>
            </div>
        );
    }

    // Check if no roles exist (seeds not applied)
    if (roles.length === 0) {
        return (
            <div className="roles-permissions">
                <div className="roles-header">
                    <h2>👥 Gerenciamento de Papéis e Permissões</h2>
                </div>
                <div className="roles-empty-state">
                    <div className="empty-state-icon">⚠️</div>
                    <h3>Nenhum papel encontrado</h3>
                    <p>
                        Os papéis padrão (root, admin, user) não foram
                        encontrados no sistema. Isso pode indicar que o schema
                        do banco de dados não foi aplicado.
                    </p>
                    <div className="empty-state-instructions">
                        <p>
                            <strong>Para corrigir, execute no terminal:</strong>
                        </p>
                        <code>
                            cd backend/database/schema && psql -d ehopdb_dev -f
                            init.sql
                        </code>
                    </div>
                    <button className="retry-btn" onClick={() => loadData()}>
                        🔄 Tentar Novamente
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="roles-permissions settings-section">
            <div className="roles-header">
                <h2>👥 Gerenciamento de Papéis e Permissões</h2>
                <p className="roles-description">
                    Configure os papéis de usuário e suas permissões de acesso
                    ao sistema.
                </p>
            </div>

            {message && (
                <div className="roles-success">
                    {message}
                    <button onClick={() => setMessage("")}>×</button>
                </div>
            )}
            {error && (
                <div className="roles-error">
                    {error}
                    <button onClick={() => setError("")}>×</button>
                </div>
            )}

            <div className="roles-layout">
                {/* Roles List */}
                <div className="roles-sidebar">
                    <div className="sidebar-header">
                        <h3>Papéis</h3>
                        <button
                            className="create-role-btn"
                            onClick={() => setShowCreateModal(true)}
                            title="Criar novo papel"
                        >
                            + Novo
                        </button>
                    </div>

                    <div className="roles-list">
                        {roles.map((rwp) => (
                            <div
                                key={rwp.role.id}
                                className={`role-item ${selectedRole?.id === rwp.role.id ? "selected" : ""} ${rwp.role.is_system ? "system" : ""}`}
                                onClick={() => setSelectedRole(rwp.role)}
                            >
                                <div className="role-info">
                                    <span className="role-name">
                                        {rwp.role.display_name}
                                    </span>
                                    <span className="role-code">
                                        {rwp.role.name}
                                    </span>
                                </div>
                                <div className="role-meta">
                                    <span
                                        className="role-priority"
                                        title={`Prioridade: ${rwp.role.priority}`}
                                    >
                                        {getPriorityLabel(rwp.role.priority)}
                                    </span>
                                    {rwp.role.is_system && (
                                        <span
                                            className="system-badge"
                                            title="Papel de sistema"
                                        >
                                            🔒
                                        </span>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Permissions Panel */}
                <div className="permissions-panel">
                    {selectedRole ? (
                        <>
                            <div className="permissions-header">
                                <div className="selected-role-info">
                                    <h3>{selectedRole.display_name}</h3>
                                    <p className="role-description">
                                        {selectedRole.description ||
                                            "Sem descrição"}
                                    </p>
                                </div>
                                <div className="role-actions">
                                    {!selectedRole.is_system && (
                                        <>
                                            <button
                                                className="edit-role-btn"
                                                onClick={() =>
                                                    setShowEditModal(true)
                                                }
                                            >
                                                ✏️ Editar
                                            </button>
                                            <button
                                                className="delete-role-btn"
                                                onClick={() =>
                                                    handleDeleteRole(
                                                        selectedRole.id,
                                                    )
                                                }
                                            >
                                                🗑️ Excluir
                                            </button>
                                        </>
                                    )}
                                    {selectedRole.is_system &&
                                        selectedRole.name !== "root" && (
                                            <button
                                                className="edit-role-btn"
                                                onClick={() =>
                                                    setShowEditModal(true)
                                                }
                                            >
                                                ✏️ Editar
                                            </button>
                                        )}
                                </div>
                            </div>

                            {selectedRole.name === "root" && (
                                <div className="root-warning">
                                    ⚠️ O papel Root tem todas as permissões e
                                    não pode ser modificado.
                                </div>
                            )}

                            <div className="permissions-categories-list">
                                {Object.entries(permissionsByCategory).map(
                                    ([category, perms]) => {
                                        const enabledCount = perms.filter(
                                            (p) =>
                                                rolePermissions[
                                                    selectedRole.id
                                                ]?.[p.id],
                                        ).length;
                                        const totalCount = perms.length;
                                        const isAllEnabled =
                                            enabledCount === totalCount;
                                        const isNoneEnabled =
                                            enabledCount === 0;

                                        return (
                                            <div
                                                key={category}
                                                className="category-summary-row"
                                            >
                                                <div className="category-info">
                                                    <span className="category-icon">
                                                        {getCategoryIcon(
                                                            category,
                                                        )}
                                                    </span>
                                                    <div className="category-details">
                                                        <span className="category-name">
                                                            {category}
                                                        </span>
                                                        <span className="category-status">
                                                            {isAllEnabled ? (
                                                                <span className="status-badge all">
                                                                    Todos
                                                                </span>
                                                            ) : isNoneEnabled ? (
                                                                <span className="status-badge none">
                                                                    Nenhum
                                                                </span>
                                                            ) : (
                                                                <span className="status-badge partial">
                                                                    {
                                                                        enabledCount
                                                                    }
                                                                    /
                                                                    {totalCount}
                                                                </span>
                                                            )}
                                                        </span>
                                                    </div>
                                                </div>
                                                <button
                                                    className="configure-btn"
                                                    onClick={() => {
                                                        setActiveCategory({
                                                            name: category,
                                                            perms: perms,
                                                        });
                                                        setShowPermissionsModal(
                                                            true,
                                                        );
                                                    }}
                                                >
                                                    ⚙️ Configurar
                                                </button>
                                            </div>
                                        );
                                    },
                                )}
                            </div>
                        </>
                    ) : (
                        <div className="no-role-selected">
                            <p>Selecione um papel para ver suas permissões</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Permissions Modal */}
            {showPermissionsModal && activeCategory && (
                <div
                    className="modal-overlay"
                    onClick={() => setShowPermissionsModal(false)}
                >
                    <div
                        className="modal-content permissions-modal"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="modal-header">
                            <h3>
                                {getCategoryIcon(activeCategory.name)}{" "}
                                {activeCategory.name}
                            </h3>
                            <button
                                className="close-modal-btn"
                                onClick={() => setShowPermissionsModal(false)}
                            >
                                ×
                            </button>
                        </div>

                        <div className="modal-subheader">
                            <p>
                                Configurando permissões para{" "}
                                <strong>{selectedRole.display_name}</strong>
                            </p>
                            {selectedRole.name !== "root" && (
                                <div className="category-actions">
                                    <button
                                        className="select-all-btn"
                                        onClick={() =>
                                            handleSelectAllCategory(
                                                activeCategory.perms,
                                                true,
                                            )
                                        }
                                    >
                                        Todos
                                    </button>
                                    <button
                                        className="select-none-btn"
                                        onClick={() =>
                                            handleSelectAllCategory(
                                                activeCategory.perms,
                                                false,
                                            )
                                        }
                                    >
                                        Nenhum
                                    </button>
                                </div>
                            )}
                        </div>

                        <div className="modal-permissions-list">
                            {activeCategory.perms.map((perm) => (
                                <label
                                    key={perm.id}
                                    className={`permission-item ${
                                        selectedRole.name === "root"
                                            ? "disabled"
                                            : ""
                                    }`}
                                >
                                    <input
                                        type="checkbox"
                                        checked={
                                            selectedRole.name === "root" ||
                                            !!rolePermissions[
                                                selectedRole.id
                                            ]?.[perm.id]
                                        }
                                        onChange={() =>
                                            handlePermissionToggle(perm.id)
                                        }
                                        disabled={selectedRole.name === "root"}
                                    />
                                    <span className="permission-icon">
                                        {getActionIcon(perm.action)}
                                    </span>
                                    <div className="permission-details">
                                        <span className="permission-name">
                                            {perm.display_name}
                                        </span>
                                        <span className="permission-description">
                                            {perm.description}
                                        </span>
                                    </div>
                                </label>
                            ))}
                        </div>

                        <div className="modal-actions">
                            <button
                                className="modal-confirm"
                                onClick={() => setShowPermissionsModal(false)}
                            >
                                Concluído
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Create Role Modal */}
            {showCreateModal && (
                <div
                    className="modal-overlay"
                    onClick={() => setShowCreateModal(false)}
                >
                    <div
                        className="modal-content"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <h3>Criar Novo Papel</h3>

                        <div className="modal-form">
                            <div className="form-group">
                                <label>Identificador (slug)</label>
                                <input
                                    type="text"
                                    value={newRole.name}
                                    onChange={(e) =>
                                        setNewRole({
                                            ...newRole,
                                            name: e.target.value
                                                .toLowerCase()
                                                .replace(/[^a-z0-9_]/g, "_"),
                                        })
                                    }
                                    placeholder="ex: financeiro, atendimento"
                                />
                                <span className="form-hint">
                                    Use apenas letras minúsculas, números e
                                    underscores
                                </span>
                            </div>

                            <div className="form-group">
                                <label>Nome de Exibição</label>
                                <input
                                    type="text"
                                    value={newRole.display_name}
                                    onChange={(e) =>
                                        setNewRole({
                                            ...newRole,
                                            display_name: e.target.value,
                                        })
                                    }
                                    placeholder="ex: Financeiro, Atendimento"
                                />
                            </div>

                            <div className="form-group">
                                <label>Descrição</label>
                                <textarea
                                    value={newRole.description}
                                    onChange={(e) =>
                                        setNewRole({
                                            ...newRole,
                                            description: e.target.value,
                                        })
                                    }
                                    placeholder="Descreva as responsabilidades deste papel..."
                                    rows={3}
                                />
                            </div>

                            <div className="form-group">
                                <label>Nível de Privilégio</label>
                                <div className="priority-selector">
                                    {priorityLevels.map((level) => (
                                        <label
                                            key={level.value}
                                            className={`priority-option ${newRole.priority_level === level.value ? "selected" : ""}`}
                                        >
                                            <input
                                                type="radio"
                                                name="priority_level"
                                                value={level.value}
                                                checked={
                                                    newRole.priority_level ===
                                                    level.value
                                                }
                                                onChange={(e) =>
                                                    setNewRole({
                                                        ...newRole,
                                                        priority_level:
                                                            e.target.value,
                                                        priority:
                                                            getPriorityFromLevel(
                                                                e.target.value,
                                                            ),
                                                    })
                                                }
                                            />
                                            <span className="priority-label">
                                                {level.label}
                                            </span>
                                            <span className="priority-desc">
                                                {level.description}
                                            </span>
                                        </label>
                                    ))}
                                </div>
                                <span className="form-hint">
                                    Define quem este papel pode gerenciar.
                                    Papéis só podem editar usuários com nível
                                    inferior.
                                </span>
                            </div>
                        </div>

                        <div className="modal-actions">
                            <button
                                className="modal-cancel"
                                onClick={() => setShowCreateModal(false)}
                            >
                                Cancelar
                            </button>
                            <button
                                className="modal-confirm"
                                onClick={handleCreateRole}
                                disabled={saving}
                            >
                                {saving ? "Criando..." : "Criar Papel"}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Edit Role Modal */}
            {showEditModal && selectedRole && (
                <div
                    className="modal-overlay"
                    onClick={() => setShowEditModal(false)}
                >
                    <div
                        className="modal-content"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <h3>Editar Papel: {selectedRole.name}</h3>

                        <div className="modal-form">
                            <div className="form-group">
                                <label>Identificador</label>
                                <input
                                    type="text"
                                    value={selectedRole.name}
                                    disabled
                                    className="disabled-input"
                                />
                                <span className="form-hint">
                                    O identificador não pode ser alterado
                                </span>
                            </div>

                            <div className="form-group">
                                <label>Nome de Exibição</label>
                                <input
                                    type="text"
                                    value={selectedRole.display_name}
                                    onChange={(e) =>
                                        setSelectedRole({
                                            ...selectedRole,
                                            display_name: e.target.value,
                                        })
                                    }
                                />
                            </div>

                            <div className="form-group">
                                <label>Descrição</label>
                                <textarea
                                    value={selectedRole.description || ""}
                                    onChange={(e) =>
                                        setSelectedRole({
                                            ...selectedRole,
                                            description: e.target.value,
                                        })
                                    }
                                    rows={3}
                                />
                            </div>

                            {!selectedRole.is_system && (
                                <div className="form-group">
                                    <label>Nível de Privilégio</label>
                                    <div className="priority-selector">
                                        {priorityLevels.map((level) => (
                                            <label
                                                key={level.value}
                                                className={`priority-option ${getPriorityLevel(selectedRole.priority) === level.value ? "selected" : ""}`}
                                            >
                                                <input
                                                    type="radio"
                                                    name="edit_priority_level"
                                                    value={level.value}
                                                    checked={
                                                        getPriorityLevel(
                                                            selectedRole.priority,
                                                        ) === level.value
                                                    }
                                                    onChange={(e) =>
                                                        setSelectedRole({
                                                            ...selectedRole,
                                                            priority:
                                                                getPriorityFromLevel(
                                                                    e.target
                                                                        .value,
                                                                ),
                                                        })
                                                    }
                                                />
                                                <span className="priority-label">
                                                    {level.label}
                                                </span>
                                                <span className="priority-desc">
                                                    {level.description}
                                                </span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {selectedRole.is_system && (
                                <div className="form-group">
                                    <label>Nível de Privilégio</label>
                                    <div className="priority-display">
                                        <span className="priority-badge">
                                            {getPriorityLabel(
                                                selectedRole.priority,
                                            )}
                                        </span>
                                        <span className="form-hint">
                                            Papéis de sistema não podem ter sua
                                            prioridade alterada.
                                        </span>
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="modal-actions">
                            <button
                                className="modal-cancel"
                                onClick={() => {
                                    setShowEditModal(false);
                                    loadData(); // Reload to reset any changes
                                }}
                            >
                                Cancelar
                            </button>
                            <button
                                className="modal-confirm"
                                onClick={handleUpdateRole}
                                disabled={saving}
                            >
                                {saving ? "Salvando..." : "Salvar Alterações"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
