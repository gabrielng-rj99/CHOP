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
                    const status = getContractStatus(contract.end_date);
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
                                        className="contracts-table-button contracts-table-button-details"
                                    >
                                        Detalhes
                                    </button>
                                    {!isArchived && (
                                        <>
                                            <button
                                                onClick={() => onEdit(contract)}
                                                className="contracts-table-button contracts-table-button-edit"
                                            >
                                                Editar
                                            </button>
                                            <button
                                                onClick={() =>
                                                    onArchive(contract.id)
                                                }
                                                className="contracts-table-button contracts-table-button-archive"
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
                                            className="contracts-table-button contracts-table-button-unarchive"
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
