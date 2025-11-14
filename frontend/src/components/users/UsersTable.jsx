import React from "react";
import { getRoleName, formatDate } from "../../utils/userHelpers";
import "./UsersTable.css";

export default function UsersTable({
    filteredUsers,
    currentUser,
    onEdit,
    onBlock,
    onUnlock,
    onDelete,
}) {
    if (filteredUsers.length === 0) {
        return (
            <div className="users-table-empty">
                <p>Nenhum usuário encontrado</p>
            </div>
        );
    }

    return (
        <table className="users-table">
            <thead>
                <tr>
                    <th>Nome de Usuário</th>
                    <th>Nome de Exibição</th>
                    <th>Função</th>
                    <th className="status">Status</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredUsers.map((user) => {
                    console.log("User row:", user);
                    const isBlocked = user.lock_level >= 3;
                    const isCurrentUser =
                        user.username === currentUser?.username;

                    return (
                        <tr
                            key={user.username}
                            className={isBlocked ? "blocked" : ""}
                        >
                            <td>
                                {user.username}
                                {isCurrentUser && (
                                    <span className="users-table-current-badge">
                                        VOCÊ
                                    </span>
                                )}
                            </td>
                            <td>{user.display_name || "-"}</td>
                            <td>
                                <span
                                    className={`users-table-role ${
                                        user.role === "full_admin"
                                            ? "full-admin"
                                            : user.role === "admin"
                                              ? "admin"
                                              : "user"
                                    }`}
                                >
                                    {getRoleName(user.role)}
                                </span>
                            </td>
                            <td className="status">
                                <span
                                    className={`users-table-status ${
                                        isBlocked ? "blocked" : "active"
                                    }`}
                                >
                                    {isBlocked ? "Bloqueado" : "Ativo"}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="users-table-actions">
                                    <button
                                        onClick={() => onEdit(user)}
                                        className="users-table-icon-button"
                                        title="Editar"
                                    >
                                        <svg
                                            width="22"
                                            height="22"
                                            viewBox="0 0 24 24"
                                            fill="none"
                                            stroke="#3498db"
                                            strokeWidth="2"
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                        >
                                            <path d="M12 20h9" />
                                            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z" />
                                        </svg>
                                    </button>
                                    {!isCurrentUser && (
                                        <>
                                            {isBlocked ? (
                                                <button
                                                    onClick={() =>
                                                        onUnlock(user.username)
                                                    }
                                                    className="users-table-icon-button"
                                                    title="Desbloquear"
                                                >
                                                    <svg
                                                        width="22"
                                                        height="22"
                                                        viewBox="0 0 24 24"
                                                        fill="none"
                                                        stroke="#27ae60"
                                                        strokeWidth="2"
                                                        strokeLinecap="round"
                                                        strokeLinejoin="round"
                                                    >
                                                        <rect
                                                            x="3"
                                                            y="11"
                                                            width="18"
                                                            height="11"
                                                            rx="2"
                                                            ry="2"
                                                        ></rect>
                                                        <path d="M7 11V7a5 5 0 0 1 10 0" />
                                                    </svg>
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() =>
                                                        onBlock(user.username)
                                                    }
                                                    className="users-table-icon-button"
                                                    title="Bloquear"
                                                >
                                                    <svg
                                                        width="22"
                                                        height="22"
                                                        viewBox="0 0 24 24"
                                                        fill="none"
                                                        stroke="#e67e22"
                                                        strokeWidth="2"
                                                        strokeLinecap="round"
                                                        strokeLinejoin="round"
                                                    >
                                                        <rect
                                                            x="3"
                                                            y="11"
                                                            width="18"
                                                            height="11"
                                                            rx="2"
                                                            ry="2"
                                                        ></rect>
                                                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                                        <line
                                                            x1="12"
                                                            y1="17"
                                                            x2="12"
                                                            y2="17"
                                                        />
                                                    </svg>
                                                </button>
                                            )}
                                            <button
                                                onClick={() =>
                                                    onDelete(user.username)
                                                }
                                                className="users-table-icon-button"
                                                title="Deletar"
                                            >
                                                <svg
                                                    width="22"
                                                    height="22"
                                                    viewBox="0 0 24 24"
                                                    fill="none"
                                                    stroke="#e74c3c"
                                                    strokeWidth="2"
                                                    strokeLinecap="round"
                                                    strokeLinejoin="round"
                                                >
                                                    <polyline points="3 6 5 6 21 6"></polyline>
                                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m5 0V4a2 2 0 0 1 2-2h0a2 2 0 0 1 2 2v2"></path>
                                                    <line
                                                        x1="10"
                                                        y1="11"
                                                        x2="10"
                                                        y2="17"
                                                    ></line>
                                                    <line
                                                        x1="14"
                                                        y1="11"
                                                        x2="14"
                                                        y2="17"
                                                    ></line>
                                                </svg>
                                            </button>
                                        </>
                                    )}
                                </div>
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
