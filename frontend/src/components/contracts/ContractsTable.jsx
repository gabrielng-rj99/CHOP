/*
 * This file is part of Entity Hub Open Project.
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from "react";
import {
    formatDate,
    getContractStatus,
    getClientName,
    getCategoryName,
} from "../../utils/contractHelpers";
import "./ContractsTable.css";
import InfoIcon from "../../assets/icons/info.svg";
import EditIcon from "../../assets/icons/edit.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";

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
                                        <img
                                            src={InfoIcon}
                                            alt="Detalhes"
                                            style={{
                                                width: "22px",
                                                height: "22px",
                                                filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                            }}
                                        />
                                    </button>
                                    {!isArchived && (
                                        <>
                                            <button
                                                onClick={() => onEdit(contract)}
                                                className="contracts-table-icon-button"
                                                title="Editar"
                                            >
                                                <img
                                                    src={EditIcon}
                                                    alt="Editar"
                                                    style={{
                                                        width: "22px",
                                                        height: "22px",
                                                        filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                                    }}
                                                />
                                            </button>
                                            <button
                                                onClick={() =>
                                                    onArchive(contract.id)
                                                }
                                                className="contracts-table-icon-button"
                                                title="Arquivar"
                                            >
                                                <img
                                                    src={ArchiveIcon}
                                                    alt="Arquivar"
                                                    style={{
                                                        width: "22px",
                                                        height: "22px",
                                                        filter: "invert(64%) sepia(81%) saturate(455%) hue-rotate(359deg) brightness(98%) contrast(91%)",
                                                    }}
                                                />
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
                                            <img
                                                src={UnarchiveIcon}
                                                alt="Desarquivar"
                                                style={{
                                                    width: "22px",
                                                    height: "22px",
                                                    filter: "invert(62%) sepia(34%) saturate(760%) hue-rotate(88deg) brightness(93%) contrast(81%)",
                                                }}
                                            />
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
