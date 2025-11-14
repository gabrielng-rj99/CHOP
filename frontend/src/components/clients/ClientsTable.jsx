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
                                        className="clients-table-button clients-table-button-edit"
                                    >
                                        Editar
                                    </button>
                                    <button
                                        onClick={() =>
                                            openDependentsModal(client)
                                        }
                                        className="clients-table-button clients-table-button-dependents"
                                    >
                                        Dependentes
                                    </button>
                                    {isArchived ? (
                                        <button
                                            onClick={() =>
                                                unarchiveClient(client.id)
                                            }
                                            className="clients-table-button clients-table-button-unarchive"
                                        >
                                            Desarquivar
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() =>
                                                archiveClient(client.id)
                                            }
                                            className="clients-table-button clients-table-button-archive"
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
