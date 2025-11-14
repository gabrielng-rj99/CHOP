import React from "react";
import {
    formatDate,
    getContractStatus,
    getClientName,
    getCategoryName,
} from "../../utils/contractHelpers";

export default function ContractsTable({
    filteredContracts,
    clients,
    categories,
    onViewDetails,
    onEdit,
    onArchive,
    onUnarchive,
}) {
    if (filteredContracts.length === 0) {
        return (
            <div style={{ padding: "40px", textAlign: "center" }}>
                <p style={{ fontSize: "16px", color: "#7f8c8d" }}>
                    Nenhum contrato encontrado
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
                        Modelo
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
                        Cliente
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
                        Categoria
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
                        Vencimento
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
                {filteredContracts.map((contract) => {
                    const status = getContractStatus(contract.end_date);
                    const isArchived = !!contract.archived_at;

                    return (
                        <tr
                            key={contract.id}
                            style={{
                                borderBottom: "1px solid #ecf0f1",
                                opacity: isArchived ? 0.6 : 1,
                            }}
                        >
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                <div style={{ fontWeight: "500" }}>
                                    {contract.model || "-"}
                                </div>
                                {contract.product_key && (
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginTop: "4px",
                                        }}
                                    >
                                        {contract.product_key}
                                    </div>
                                )}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                {getClientName(contract.client_id, clients)}
                                {contract.dependent && (
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginTop: "4px",
                                        }}
                                    >
                                        Dep: {contract.dependent.name}
                                    </div>
                                )}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                {getCategoryName(contract.line_id, categories)}
                                {contract.line && (
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginTop: "4px",
                                        }}
                                    >
                                        {contract.line.line}
                                    </div>
                                )}
                            </td>
                            <td
                                style={{
                                    padding: "16px",
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                {formatDate(contract.end_date)}
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
                                        background: `${status.color}20`,
                                        color: status.color,
                                    }}
                                >
                                    {isArchived ? "Arquivado" : status.status}
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
                                        onClick={() => onViewDetails(contract)}
                                        style={{
                                            padding: "6px 12px",
                                            background: "#9b59b6",
                                            color: "white",
                                            border: "none",
                                            borderRadius: "4px",
                                            cursor: "pointer",
                                            fontSize: "13px",
                                        }}
                                    >
                                        Detalhes
                                    </button>
                                    {!isArchived && (
                                        <>
                                            <button
                                                onClick={() => onEdit(contract)}
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
                                            <button
                                                onClick={() =>
                                                    onArchive(contract.id)
                                                }
                                                style={{
                                                    padding: "6px 12px",
                                                    background: "#95a5a6",
                                                    color: "white",
                                                    border: "none",
                                                    borderRadius: "4px",
                                                    cursor: "pointer",
                                                    fontSize: "13px",
                                                }}
                                            >
                                                Arquivar
                                            </button>
                                        </>
                                    )}
                                    {isArchived && (
                                        <button
                                            onClick={() =>
                                                onUnarchive(contract.id)
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
                                            Desarquivar
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
