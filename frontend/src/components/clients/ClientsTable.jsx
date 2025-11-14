import React from "react";
import "./ClientsTable.css";

export default function ClientsTable({
    filteredClients,
    openEditModal,
    openDependentsModal,
    archiveClient,
    unarchiveClient,
}) {
    if (filteredClients.length === 0) {
        return (
            <div className="clients-table-empty">Nenhum cliente encontrado</div>
        );
    }

    return (
        <table className="clients-table">
            <thead>
                <tr>
                    <th>NOME</th>
                    <th>CPF/CNPJ</th>
                    <th>EMAIL</th>
                    <th>TELEFONE</th>
                    <th>STATUS</th>
                    <th className="actions">AÇÕES</th>
                </tr>
            </thead>
            <tbody>
                {filteredClients.map((client) => {
                    const statusColor =
                        client.status === "ativo" ? "#27ae60" : "#95a5a6";
                    const isArchived = !!client.archived_at;
                    return (
                        <tr key={client.id}>
                            <td className="name">
                                {client.name}
                                {client.nickname && (
                                    <div className="clients-table-nickname">
                                        {client.nickname}
                                    </div>
                                )}
                            </td>
                            <td className="registration">
                                {client.registration_id || "-"}
                            </td>
                            <td className="email">{client.email || "-"}</td>
                            <td className="phone">{client.phone || "-"}</td>
                            <td>
                                <span
                                    className={`clients-table-status ${isArchived ? "archived" : "active"}`}
                                    style={{
                                        background: statusColor + "20",
                                        color: statusColor,
                                    }}
                                >
                                    {isArchived ? "Arquivado" : client.status}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="clients-table-actions">
                                    <button
                                        onClick={() => openEditModal(client)}
                                        className="clients-table-icon-button"
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
                                    <button
                                        onClick={() =>
                                            openDependentsModal(client)
                                        }
                                        className="clients-table-icon-button"
                                        title="Filiais/Dependentes"
                                    >
                                        <svg
                                            width="22"
                                            height="22"
                                            viewBox="0 0 24 24"
                                            fill="none"
                                            stroke="#9b59b6"
                                            strokeWidth="2"
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                        >
                                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                            <circle
                                                cx="9"
                                                cy="7"
                                                r="4"
                                            ></circle>
                                            <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                            <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                        </svg>
                                    </button>
                                    {isArchived ? (
                                        <button
                                            onClick={() =>
                                                unarchiveClient(client.id)
                                            }
                                            className="clients-table-icon-button"
                                            title="Desarquivar"
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
                                                <polyline points="21 8 21 21 3 21 3 8"></polyline>
                                                <rect
                                                    x="1"
                                                    y="3"
                                                    width="22"
                                                    height="5"
                                                ></rect>
                                                <polyline points="10 12 12 14 14 12"></polyline>
                                            </svg>
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() =>
                                                archiveClient(client.id)
                                            }
                                            className="clients-table-icon-button"
                                            title="Arquivar"
                                        >
                                            <svg
                                                width="22"
                                                height="22"
                                                viewBox="0 0 24 24"
                                                fill="none"
                                                stroke="#f39c12"
                                                strokeWidth="2"
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                            >
                                                <polyline points="21 8 21 21 3 21 3 8"></polyline>
                                                <rect
                                                    x="1"
                                                    y="3"
                                                    width="22"
                                                    height="5"
                                                ></rect>
                                                <line
                                                    x1="10"
                                                    y1="12"
                                                    x2="14"
                                                    y2="12"
                                                ></line>
                                            </svg>
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
