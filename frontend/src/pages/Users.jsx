import React, { useState, useEffect } from "react";
import { usersApi } from "../api/usersApi";
import {
    filterUsers,
    getInitialFormData,
    formatUserForEdit,
} from "../utils/userHelpers";
import UsersTable from "../components/users/UsersTable";
import UserModal from "../components/users/UserModal";
import AuditLogsTable from "../components/audit/AuditLogsTable";
import "./Users.css";

export default function Users({
    token,
    apiUrl,
    user,
    onLogout,
    onTokenExpired,
}) {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [modalError, setModalError] = useState("");
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
            const data = await usersApi.loadUsers(
                apiUrl,
                token,
                onTokenExpired,
            );
            setUsers(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCreateUser = async () => {
        setModalError("");
        try {
            await usersApi.createUser(apiUrl, token, formData, onTokenExpired);
            await loadUsers();
            closeModal();
            setSuccess("Usuário criado com sucesso!");
            setTimeout(() => setSuccess(""), 3000);
        } catch (err) {
            setModalError(err.message);
        }
    };

    const handleUpdateUser = async () => {
        setModalError("");
        try {
            const payload = {
                display_name: formData.display_name,
                role: formData.role,
            };

            if (formData.password) {
                payload.password = formData.password;
            }

            if (
                formData.username &&
                formData.username !== selectedUser.username
            ) {
                payload.username = formData.username;
            }

            const isUpdatingSelf = selectedUser.username === user.username;
            const isOnlyChangingPassword =
                formData.password &&
                formData.display_name === selectedUser.display_name &&
                formData.role === selectedUser.role &&
                formData.username === selectedUser.username;

            await usersApi.updateUser(
                apiUrl,
                token,
                selectedUser.username,
                payload,
                onTokenExpired,
            );
            await loadUsers();
            closeModal();
            setSuccess("Usuário atualizado com sucesso!");
            setTimeout(() => setSuccess(""), 3000);

            // Se alterou a própria senha apenas, não desloga
            if (isUpdatingSelf && !isOnlyChangingPassword) {
                // Qualquer alteração que não seja só senha causa logout
                setTimeout(() => {
                    alert(
                        "Suas informações foram alteradas. Você será deslogado.",
                    );
                    onLogout();
                }, 1500);
            }
        } catch (err) {
            setModalError(err.message);
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
            await usersApi.blockUser(apiUrl, token, username, onTokenExpired);
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
            await usersApi.unlockUser(apiUrl, token, username, onTokenExpired);
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
            await usersApi.deleteUser(apiUrl, token, username, onTokenExpired);
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
        setModalError("");
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            handleCreateUser();
        } else {
            handleUpdateUser();
        }
    };

    function compareAlphaNum(a, b) {
        const regex = /(.*?)(\d+)$/;
        const aMatch = (a.username || "").match(regex);
        const bMatch = (b.username || "").match(regex);

        if (aMatch && bMatch && aMatch[1] === bMatch[1]) {
            // Se prefixo igual, compara número como inteiro
            return parseInt(aMatch[2], 10) - parseInt(bMatch[2], 10);
        }
        // Caso contrário, ordena normalmente
        return (a.username || "").localeCompare(b.username || "");
    }

    const filteredUsers = filterUsers(
        [...users].sort(compareAlphaNum),
        searchTerm,
    );

    if (loading) {
        return (
            <div className="users-loading">
                <div className="users-loading-text">Carregando usuários...</div>
            </div>
        );
    }

    return (
        <div className="users-container">
            <div className="users-header">
                <h1 className="users-title">Gerenciamento de Usuários</h1>
                <div className="users-button-group">
                    <button
                        onClick={loadUsers}
                        className="users-button-secondary"
                    >
                        Atualizar
                    </button>
                    {["admin", "root"].includes(user.role) && (
                        <button
                            onClick={openCreateModal}
                            className="users-button"
                        >
                            + Novo Usuário
                        </button>
                    )}
                </div>
            </div>

            {error && <div className="users-error">{error}</div>}

            {success && <div className="users-success">{success}</div>}

            <div className="users-search-container">
                <input
                    type="text"
                    placeholder="Buscar por nome de usuário, nome de exibição ou função..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="users-search-input"
                />
            </div>

            <div className="users-table-wrapper">
                {/* <div className="users-table-header">
                    <h2 className="users-table-header-title">Usuários</h2>
                </div>*/}
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
                error={modalError}
                currentUserRole={user.role}
            />

            {/* Exemplo de uso: AuditLogsTable recebe lista de usuários */}
            {/* <AuditLogsTable logs={logs} users={users} ... /> */}
        </div>
    );
}
