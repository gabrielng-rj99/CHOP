import React from "react";
import {
    formatDate,
    getContractStatus,
    getClientName,
    getCategoryName,
} from "../../utils/contractHelpers";
import "./ContractsTable.css";

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
            <div className="contracts-table-empty">
                <p>Nenhum contrato encontrado</p>
            </div>
        );
    }

    return (
        <table className="contracts-table">
            <thead>
                <tr>
                    <th>Modelo</th>
                    <th>Cliente</th>
                    <th>Categoria</th>
                    <th>Vencimento</th>
                    <th className="status">Status</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredContracts.map((contract) => {
                    const status = getContractStatus(contract);
                    const isArchived = !!contract.archived_at;

                    return (
                        <tr
                            key={contract.id}
                            className={isArchived ? "archived" : ""}
                        >
                            <td>
                                <div className="contracts-table-model">
                                    {contract.model || "-"}
                                </div>
                                {contract.product_key && (
                                    <div className="contracts-table-product-key">
                                        {contract.product_key}
                                    </div>
                                )}
                            </td>
                            <td>
                                {getClientName(contract.client_id, clients)}
                                {contract.dependent && (
                                    <div className="contracts-table-dependent">
                                        Dep: {contract.dependent.name}
                                    </div>
                                )}
                            </td>
                            <td>
                                {getCategoryName(contract.line_id, categories)}
                                {contract.line && (
                                    <div className="contracts-table-line">
                                        {contract.line.line}
                                    </div>
                                )}
                            </td>
                            <td>{formatDate(contract.end_date)}</td>
                            <td className="status">
                                <span
                                    className="contracts-table-status"
                                    style={{
                                        background: `${status.color}20`,
                                        color: status.color,
                                    }}
                                >
                                    {isArchived ? "Arquivado" : status.status}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="contracts-table-actions">
                                    <button
                                        onClick={() => onViewDetails(contract)}
                                        className="contracts-table-icon-button"
                                        title="Detalhes"
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
                                            <circle
                                                cx="12"
                                                cy="12"
                                                r="10"
                                            ></circle>
                                            <line
                                                x1="12"
                                                y1="16"
                                                x2="12"
                                                y2="12"
                                            ></line>
                                            <line
                                                x1="12"
                                                y1="8"
                                                x2="12.01"
                                                y2="8"
                                            ></line>
                                        </svg>
                                    </button>
                                    {!isArchived && (
                                        <>
                                            <button
                                                onClick={() => onEdit(contract)}
                                                className="contracts-table-icon-button"
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
                                                    onArchive(contract.id)
                                                }
                                                className="contracts-table-icon-button"
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
                                        </>
                                    )}
                                    {isArchived && (
                                        <button
                                            onClick={() =>
                                                onUnarchive(contract.id)
                                            }
                                            className="contracts-table-icon-button"
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
