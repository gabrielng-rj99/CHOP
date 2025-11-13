import React, { useState, useEffect } from "react";

export default function Users({ token, apiUrl, user }) {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [searchTerm, setSearchTerm] = useState("");
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [selectedUser, setSelectedUser] = useState(null);
    const [formData, setFormData] = useState({
        username: "",
        display_name: "",
        password: "",
        role: "user",
    });

    useEffect(() => {
        loadUsers();
    }, []);

    const loadUsers = async () => {
        setLoading(true);
        setError("");

        try {
            const response = await fetch(`${apiUrl}/api/users`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            });

            if (!response.ok) {
                throw new Error("Erro ao carregar usuários");
            }

            const data = await response.json();
            setUsers(data.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const createUser = async () => {
        try {
            const response = await fetch(`${apiUrl}/api/users`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(formData),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao criar usuário");
            }

            await loadUsers();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateUser = async () => {
        try {
            const payload = {
                display_name: formData.display_name,
                role: formData.role,
            };

            if (formData.password) {
                payload.password = formData.password;
            }

            const response = await fetch(
                `${apiUrl}/api/users/${selectedUser.username}`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(payload),
                }
            );

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao atualizar usuário");
            }

            await loadUsers();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const blockUser = async (username) => {
        if (username === user.username) {
            setError("Você não pode bloquear a si mesmo!");
            return;
        }

        if (
            !window.confirm(
                `Tem certeza que deseja bloquear o usuário ${username}?`
            )
        )
            return;

        try {
            const response = await fetch(
                `${apiUrl}/api/users/${username}/block`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                }
            );

            if (!response.ok) {
                throw new Error("Erro ao bloquear usuário");
            }

            await loadUsers();
        } catch (err) {
            setError(err.message);
        }
    };

    const unlockUser = async (username) => {
        try {
            const response = await fetch(
                `${apiUrl}/api/users/${username}/unlock`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                }
            );

            if (!response.ok) {
                throw new Error("Erro ao desbloquear usuário");
            }

            await loadUsers();
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData({
            username: "",
            display_name: "",
            password: "",
            role: "user",
        });
        setShowModal(true);
    };

    const openEditModal = (selectedUserData) => {
        setModalMode("edit");
        setSelectedUser(selectedUserData);
        setFormData({
            username: selectedUserData.username,
            display_name: selectedUserData.display_name || "",
            password: "",
            role: selectedUserData.role || "user",
        });
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedUser(null);
        setError("");
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            createUser();
        } else {
            updateUser();
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        const date = new Date(dateString);
        return date.toLocaleDateString("pt-BR") + " " + date.toLocaleTimeString("pt-BR");
    };

    const filteredUsers = users.filter((u) => {
        if (searchTerm === "") return true;
        const search = searchTerm.toLowerCase();
        return (
            u.username?.toLowerCase().includes(search) ||
            u.display_name?.toLowerCase().includes(search) ||
            u.role?.toLowerCase().includes(search)
        );
    });

    const canEditUser = (targetUser) => {
        if (user.role === "full_admin") return true;
        if (user.role === "admin" && targetUser.role !== "full_admin")
            return true;
        return false;
    };

    const canBlockUser = (targetUser) => {
        if (user.role !== "full_admin") return false;
        return targetUser.username !== user.username;
    };

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "60px" }}>
                <div style={{ fontSize: "18px", color: "#7f8c8d" }}>
                    Carregando usuários...
                </div>
            </div>
        );
    }

    return (
        <div>
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "30px",
                }}
            >
                <h1 style={{ fontSize: "32px", color: "#2c3e50", margin: 0 }}>
                    Usuários
                </h1>
                <div style={{ display: "flex", gap: "12px" }}>
                    <button
                        onClick={loadUsers}
                        style={{
                            padding: "10px 20px",
                            background: "white",
                            color: "#3498db",
                            border: "1px solid #3498db",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                        }}
                    >
                        Atualizar
                    </button>
                    <button
                        onClick={openCreateModal}
                        style={{
                            padding: "10px 20px",
                            background: "#27ae60",
                            color: "white",
                            border: "none",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                            fontWeight: "600",
                        }}
                    >
                        + Novo Usuário
                    </button>
                </div>
            </div>

            {error && (
                <div
                    style={{
                        background: "#fee",
                        color: "#c33",
                        padding: "16px",
                        borderRadius: "4px",
                        border: "1px solid #fcc",
                        marginBottom: "20px",
                    }}
                >
                    {error}
                </div>
            )}

            <div style={{ marginBottom: "24px" }}>
                <input
                    type="text"
                    placeholder="Buscar por username, nome ou role..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    style={{
                        width: "100%",
                        maxWidth: "500px",
                        padding: "10px 16px",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                />
            </div>

            <div
                style={{
                    background: "white",
                    borderRadius: "8px",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                    border: "1px solid #ecf0f1",
                    overflow: "hidden",
                }}
            >
                {filteredUsers.length === 0 ? (
                    <div
                        style={{
                            padding: "40px",
                            textAlign: "center",
                            color: "#7f8c8d",
                        }}
                    >
                        Nenhum usuário encontrado
                    </div>
                ) : (
                    <table
                        style={{ width: "100%", borderCollapse: "collapse" }}
                    >
                        <thead>
                            <tr
                                style={{
                                    background: "#f8f9fa",
                                    borderBottom: "2px solid #ecf0f1",
                                }}
                            >
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    USERNAME
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    NOME
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    ROLE
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    STATUS
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    CRIADO EM
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "center",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    AÇÕES
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredUsers.map((u) => {
                                const isBlocked = !!u.blocked_at;
                                const isCurrentUser = u.username === user.username;
                                const roleColor =
                                    u.role === "full_admin"
                                        ? "#e74c3c"
                                        : u.role === "admin"
                                        ? "#f39c12"
                                        : "#3498db";

                                return (
                                    <tr
                                        key={u.id}
                                        style={{
                                            borderBottom: "1px solid #ecf0f1",
                                            background: isCurrentUser
                                                ? "#f0f8ff"
                                                : "white",
                                        }}
                                    >
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#2c3e50",
                                                fontWeight: "500",
                                                fontFamily: "monospace",
                                            }}
                                        >
                                            {u.username}
                                            {isCurrentUser && (
                                                <span
                                                    style={{
                                                        marginLeft: "8px",
                                                        fontSize: "11px",
                                                        padding: "2px 6px",
                                                        background: "#3498db",
                                                        color: "white",
                                                        borderRadius: "10px",
                                                    }}
                                                >
                                                    você
                                                </span>
                                            )}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#2c3e50",
                                            }}
                                        >
                                            {u.display_name || "-"}
                                        </td>
                                        <td style={{ padding: "16px" }}>
                                            <span
                                                style={{
                                                    display: "inline-block",
                                                    padding: "4px 12px",
                                                    borderRadius: "12px",
                                                    fontSize: "12px",
                                                    fontWeight: "600",
                                                    background: roleColor + "20",
                                                    color: roleColor,
                                                    textTransform: "capitalize",
                                                }}
                                            >
                                                {u.role}
                                            </span>
                                        </td>
                                        <td style={{ padding: "16px" }}>
                                            <span
                                                style={{
                                                    display: "inline-block",
                                                    padding: "4px 12px",
                                                    borderRadius: "12px",
                                                    fontSize: "12px",
                                                    fontWeight: "600",
                                                    background: isBlocked
                                                        ? "#e74c3c20"
                                                        : "#27ae6020",
                                                    color: isBlocked
                                                        ? "#e74c3c"
                                                        : "#27ae60",
                                                }}
                                            >
                                                {isBlocked ? "Bloqueado" : "Ativo"}
                                            </span>
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {formatDate(u.created_at)}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                textAlign: "center",
                                            }}
                                        >
                                            <div
                                                style={{
                                                    display: "flex",
                                                    gap: "8px",
                                                    justifyContent: "center",
                                                }}
                                            >
                                                {canEditUser(u) && (
                                                    <button
                                                        onClick={() =>
                                                            openEditModal(u)
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background: "#3498db",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
                                                        }}
                                                    >
                                                        Editar
                                                    </button>
                                                )}
                                                {canBlockUser(u) && (
                                                    <>
                                                        {isBlocked ? (
                                                            <button
                                                                onClick={() =>
                                                                    unlockUser(
                                                                        u.username
                                                                    )
                                                                }
                                                                style={{
                                                                    padding:
                                                                        "6px 12px",
                                                                    background:
                                                                        "#27ae60",
                                                                    color: "white",
                                                                    border: "none",
                                                                    borderRadius:
                                                                        "4px",
                                                                    cursor: "pointer",
                                                                    fontSize:
                                                                        "12px",
                                                                }}
                                                            >
                                                                Desbloquear
                                                            </button>
                                                        ) : (
                                                            <button
                                                                onClick={() =>
                                                                    blockUser(
                                                                        u.username
                                                                    )
                                                                }
                                                                style={{
                                                                    padding:
                                                                        "6px 12px",
                                                                    background:
                                                                        "#e74c3c",
                                                                    color: "white",
                                                                    border: "none",
                                                                    borderRadius:
                                                                        "4px",
                                                                    cursor: "pointer",
                                                                    fontSize:
                                                                        "12px",
                                                                }}
                                                            >
                                                                Bloquear
                                                            </button>
                                                        )}
                                                    </>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>

            {showModal && (
                <div
                    style={{
                        position: "fixed",
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: "rgba(0,0,0,0.5)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        zIndex: 1000,
                    }}
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "30px",
                            width: "90%",
                            maxWidth: "500px",
                        }}
                    >
                        <h2
                            style={{
                                marginTop: 0,
                                marginBottom: "24px",
                                fontSize: "24px",
                                color: "#2c3e50",
                            }}
                        >
                            {modalMode === "create"
                                ? "Novo Usuário"
                                : "Editar Usuário"}
                        </h2>

                        <form onSubmit={handleSubmit}>
                            {modalMode === "create" && (
                                <div style={{ marginBottom: "16px" }}>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Username *
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
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>
                            )}

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
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
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Senha {modalMode === "edit" && "(deixe em branco para não alterar)"}
                                </label>
                                <input
                                    type="password"
                                    value={formData.password}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            password: e.target.value,
                                        })
                                    }
                                    required={modalMode === "create"}
                                    minLength={12}
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                                <small style={{ color: "#7f8c8d", fontSize: "12px" }}>
                                    Mínimo 12 caracteres, contendo maiúsculas, minúsculas, números e caracteres especiais
                                </small>
                            </div>

                            <div style={{ marginBottom: "24px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Role *
                                </label>
                                <select
                                    value={formData.role}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            role: e.target.value,
                                        })
                                    }
                                    required
                                    disabled={
                                        user.role !== "full_admin" &&
                                        modalMode === "edit"
                                    }
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                >
                                    <option value="user">User</option>
                                    {(user.role === "admin" ||
                                        user.role === "full_admin") && (
                                        <option value="admin">Admin</option>
                                    )}
                                    {user.role === "full_admin" && (
                                        <option value="full_admin">
                                            Full Admin
                                        </option>
                                    )}
                                </select>
                            </div>

                            <div
                                style={{
                                    display: "flex",
                                    gap: "12px",
                                    justifyContent: "flex-end",
                                }}
                            >
                                <button
                                    type="button"
                                    onClick={closeModal}
                                    style={{
                                        padding: "10px 24px",
                                        background: "white",
                                        color: "#7f8c8d",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                    }}
                                >
                                    Cancelar
                                </button>
                                <button
                                    type="submit"
                                    style={{
                                        padding: "10px 24px",
                                        background: "#27ae60",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {modalMode === "create"
                                        ? "Criar Usuário"
                                        : "Salvar Alterações"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
