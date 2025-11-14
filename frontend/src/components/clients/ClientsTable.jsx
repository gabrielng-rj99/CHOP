import React from "react";

export default function ClientsTable({
    filteredClients,
    openEditModal,
    openDependentsModal,
    archiveClient,
    unarchiveClient,
}) {
    if (filteredClients.length === 0) {
        return (
            <div
                style={{
                    padding: "40px",
                    textAlign: "center",
                    color: "#7f8c8d",
                }}
            >
                Nenhum cliente encontrado
            </div>
        );
    }

    return (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
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
                        CPF/CNPJ
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
                        EMAIL
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
                        TELEFONE
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
                {filteredClients.map((client) => {
                    const statusColor =
                        client.status === "ativo" ? "#27ae60" : "#95a5a6";
                    const isArchived = !!client.archived_at;
                    return (
                        <tr
                            key={client.id}
                            style={{
                                borderBottom: "1px solid #ecf0f1",
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
                                {client.name}
                                {client.nickname && (
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            fontWeight: "normal",
                                        }}
                                    >
                                        {client.nickname}
                                    </div>
                                )}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#7f8c8d",
                                    fontFamily: "monospace",
                                }}
                            >
                                {client.registration_id || "-"}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#7f8c8d",
                                }}
                            >
                                {client.email || "-"}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#7f8c8d",
                                }}
                            >
                                {client.phone || "-"}
                            </td>
                            <td style={{ padding: "16px" }}>
                                <span
                                    style={{
                                        display: "inline-block",
                                        padding: "4px 12px",
                                        borderRadius: "12px",
                                        fontSize: "12px",
                                        fontWeight: "600",
                                        background: statusColor + "20",
                                        color: statusColor,
                                        textTransform: "capitalize",
                                    }}
                                >
                                    {isArchived ? "Arquivado" : client.status}
                                </span>
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
                                    <button
                                        onClick={() => openEditModal(client)}
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
                                    <button
                                        onClick={() =>
                                            openDependentsModal(client)
                                        }
                                        style={{
                                            padding: "6px 12px",
                                            background: "#9b59b6",
                                            color: "white",
                                            border: "none",
                                            borderRadius: "4px",
                                            cursor: "pointer",
                                            fontSize: "12px",
                                        }}
                                    >
                                        Dependentes
                                    </button>
                                    {isArchived ? (
                                        <button
                                            onClick={() =>
                                                unarchiveClient(client.id)
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                background: "#27ae60",
                                                color: "white",
                                                border: "none",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                                fontSize: "12px",
                                            }}
                                        >
                                            Desarquivar
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() =>
                                                archiveClient(client.id)
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                background: "#e74c3c",
                                                color: "white",
                                                border: "none",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                                fontSize: "12px",
                                            }}
                                        >
                                            Arquivar
                                        </button>
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
