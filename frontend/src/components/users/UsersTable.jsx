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
                                            padding: "6px 12px",
                                            background: "#3498db",
                                            color: "white",
                                            border: "none",
                                            borderRadius: "4px",
                                            cursor: "pointer",
                                            fontSize: "13px",
                                        }}
                                    >
                                        Editar
                                    </button>
                                    {!isCurrentUser && (
                                        <>
                                            {isBlocked ? (
                                                <button
                                                    onClick={() =>
                                                        onUnlock(user.username)
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#27ae60",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    Desbloquear
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() =>
                                                        onBlock(user.username)
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#f39c12",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    Bloquear
                                                </button>
                                            )}
                                            <button
                                                onClick={() =>
                                                    onDelete(user.username)
                                                }
                                                style={{
                                                    padding: "6px 12px",
                                                    background: "#e74c3c",
                                                    color: "white",
                                                    border: "none",
                                                    borderRadius: "4px",
                                                    cursor: "pointer",
                                                    fontSize: "13px",
                                                }}
                                            >
                                                Deletar
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
