import React from "react";
import { getRoleName, formatDate } from "../../utils/userHelpers";

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
            <div style={{ padding: "40px", textAlign: "center" }}>
                <p style={{ fontSize: "16px", color: "#7f8c8d" }}>
                    Nenhum usuário encontrado
                </p>
            </div>
        );
    }

    return (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
                <tr
                    style={{
                        background: "#f8f9fa",
                        borderBottom: "2px solid #dee2e6",
                    }}
                >
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "left",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                        }}
                    >
                        Nome de Usuário
                    </th>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "left",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                        }}
                    >
                        Nome de Exibição
                    </th>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "left",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                        }}
                    >
                        Função
                    </th>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "center",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                        }}
                    >
                        Status
                    </th>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "center",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                            width: "250px",
                        }}
                    >
                        Ações
                    </th>
                </tr>
            </thead>
            <tbody>
                {filteredUsers.map((user) => {
                    const isBlocked = !!user.blocked_at;
                    const isCurrentUser =
                        user.username === currentUser?.username;

                    return (
                        <tr
                            key={user.username}
                            style={{
                                borderBottom: "1px solid #ecf0f1",
                                opacity: isBlocked ? 0.6 : 1,
                            }}
                        >
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                    fontWeight: "500",
                                }}
                            >
                                {user.username}
                                {isCurrentUser && (
                                    <span
                                        style={{
                                            marginLeft: "8px",
                                            padding: "2px 8px",
                                            background: "#3498db20",
                                            color: "#3498db",
                                            borderRadius: "4px",
                                            fontSize: "11px",
                                            fontWeight: "600",
                                        }}
                                    >
                                        VOCÊ
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
                                {user.display_name || "-"}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                <span
                                    style={{
                                        padding: "4px 12px",
                                        borderRadius: "12px",
                                        fontSize: "12px",
                                        fontWeight: "600",
                                        background:
                                            user.role === "admin"
                                                ? "#e74c3c20"
                                                : "#95a5a620",
                                        color:
                                            user.role === "admin"
                                                ? "#e74c3c"
                                                : "#95a5a6",
                                    }}
                                >
                                    {getRoleName(user.role)}
                                </span>
                            </td>
                            <td
                                style={{ padding: "16px", textAlign: "center" }}
                            >
                                <span
                                    style={{
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
                                style={{ padding: "16px", textAlign: "center" }}
                            >
                                <div
                                    style={{
                                        display: "flex",
                                        gap: "8px",
                                        justifyContent: "center",
                                        flexWrap: "wrap",
                                    }}
                                >
                                    <button
                                        onClick={() => onEdit(user)}
                                        style={{
                                            background: "none",
                                            border: "none",
                                            padding: 0,
                                            cursor: "pointer",
                                            display: "flex",
                                            alignItems: "center",
                                        }}
                                        title="Editar"
                                    >
                                        {/* Ícone lápis (editar) */}
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
                                                    style={{
                                                        background: "none",
                                                        border: "none",
                                                        padding: 0,
                                                        cursor: "pointer",
                                                        display: "flex",
                                                        alignItems: "center",
                                                    }}
                                                    title="Desbloquear"
                                                >
                                                    {/* Ícone cadeado aberto (desbloquear) */}
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
                                                    style={{
                                                        background: "none",
                                                        border: "none",
                                                        padding: 0,
                                                        cursor: "pointer",
                                                        display: "flex",
                                                        alignItems: "center",
                                                    }}
                                                    title="Bloquear"
                                                >
                                                    {/* Ícone cadeado fechado (bloquear) */}
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
                                                style={{
                                                    background: "none",
                                                    border: "none",
                                                    padding: 0,
                                                    cursor: "pointer",
                                                    display: "flex",
                                                    alignItems: "center",
                                                }}
                                                title="Deletar"
                                            >
                                                {/* Ícone lixeira (deletar) */}
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
