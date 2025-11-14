import React, { useState, useEffect } from "react";
import { usersApi } from "../api/usersApi";
import {
    filterUsers,
    getInitialFormData,
    formatUserForEdit,
} from "../utils/userHelpers";
import UsersTable from "../components/users/UsersTable";
import UserModal from "../components/users/UserModal";

export default function Users({ token, apiUrl, user, onLogout }) {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [searchTerm, setSearchTerm] = useState("");
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [selectedUser, setSelectedUser] = useState(null);
    const [formData, setFormData] = useState(getInitialFormData());

    useEffect(() => {
        loadUsers();
    }, []);

    const loadUsers = async () => {
        setLoading(true);
        setError("");
        try {
            const data = await usersApi.loadUsers(apiUrl, token);
            setUsers(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCreateUser = async () => {
        try {
            await usersApi.createUser(apiUrl, token, formData);
            await loadUsers();
            closeModal();
            setSuccess("Usuário criado com sucesso!");
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdateUser = async () => {
        try {
            const payload = {
                display_name: formData.display_name,
                role: formData.role,
            };

            if (formData.password) {
                payload.password = formData.password;
            }

            await usersApi.updateUser(
                apiUrl,
                token,
                selectedUser.username,
                payload,
            );
            await loadUsers();
            closeModal();
            setSuccess("Usuário atualizado com sucesso!");
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleBlockUser = async (username) => {
        setError("");
        setSuccess("");

        if (username === user.username) {
            setError("Você não pode bloquear a si mesmo!");
            return;
        }

        if (
            !window.confirm(
                `Tem certeza que deseja bloquear o usuário ${username}?`,
            )
        ) {
            return;
        }

        try {
            await usersApi.blockUser(apiUrl, token, username);
            await loadUsers();
            setSuccess(`Usuário ${username} bloqueado com sucesso!`);
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnlockUser = async (username) => {
        setError("");
        setSuccess("");

        try {
            await usersApi.unlockUser(apiUrl, token, username);
            await loadUsers();
            setSuccess(`Usuário ${username} desbloqueado com sucesso!`);
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDeleteUser = async (username) => {
        setError("");
        setSuccess("");

        if (username === user.username) {
            setError("Você não pode deletar a si mesmo!");
            return;
        }

        if (
            !window.confirm(
                `Tem certeza que deseja DELETAR permanentemente o usuário ${username}?\n\nEsta ação não pode ser desfeita!`,
            )
        ) {
            return;
        }

        try {
            await usersApi.deleteUser(apiUrl, token, username);
            await loadUsers();
            setSuccess(`Usuário ${username} deletado com sucesso!`);
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData(getInitialFormData());
        setShowModal(true);
    };

    const openEditModal = (userToEdit) => {
        setModalMode("edit");
        setSelectedUser(userToEdit);
        setFormData(formatUserForEdit(userToEdit));
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedUser(null);
        setFormData(getInitialFormData());
        setError("");
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            handleCreateUser();
        } else {
            handleUpdateUser();
        }
    };

    const filteredUsers = filterUsers(users, searchTerm);

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
                    Gerenciamento de Usuários
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
                    {["admin", "full_admin"].includes(user.role) && (
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
                    )}
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

            {success && (
                <div
                    style={{
                        background: "#d4edda",
                        color: "#155724",
                        padding: "16px",
                        borderRadius: "4px",
                        border: "1px solid #c3e6cb",
                        marginBottom: "20px",
                    }}
                >
                    {success}
                </div>
            )}

            <div style={{ marginBottom: "24px" }}>
                <input
                    type="text"
                    placeholder="Buscar por nome de usuário, nome de exibição ou função..."
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
                <UsersTable
                    filteredUsers={filteredUsers}
                    currentUser={user}
                    onEdit={openEditModal}
                    onBlock={handleBlockUser}
                    onUnlock={handleUnlockUser}
                    onDelete={handleDeleteUser}
                />
            </div>

            <UserModal
                showModal={showModal}
                modalMode={modalMode}
                formData={formData}
                setFormData={setFormData}
                onSubmit={handleSubmit}
                onClose={closeModal}
            />
        </div>
    );
}
