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
import "./EntitiesTable.css";
import BranchIcon from "../../assets/icons/branch.svg";
import EditIcon from "../../assets/icons/edit.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";

export default function EntitiesTable({
    filteredClients,
    openEditModal,
    openSubEntitiesPanel,
    archiveEntity,
    unarchiveEntity,
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
                    <th>APELIDO</th>
                    <th>STATUS</th>
                    <th>CONTRATOS ATIVOS</th>
                    <th>CONTRATOS EXPIRADOS</th>
                    <th>CONTRATOS ARQUIVADOS</th>
                    <th className="actions">AÇÕES</th>
                </tr>
            </thead>
            <tbody>
                {filteredClients.map((client) => {
                    const isArchived = !!client.archived_at;
                    const hasActiveContracts =
                        (client.active_agreements || 0) > 0;
                    const effectiveStatus = hasActiveContracts
                        ? "ativo"
                        : client.status;
                    const statusColor =
                        effectiveStatus === "ativo" ? "#27ae60" : "#95a5a6";

                    return (
                        <tr key={client.id}>
                            <td className="name">{client.name}</td>
                            <td className="nickname">
                                {client.nickname || "-"}
                            </td>
                            <td>
                                <span
                                    className={`clients-table-status ${isArchived ? "archived" : "active"}`}
                                    style={{
                                        background: statusColor + "20",
                                        color: statusColor,
                                    }}
                                >
                                    {isArchived ? "Arquivado" : effectiveStatus}
                                </span>
                            </td>
                            <td className="contracts-count">
                                {client.active_agreements || 0}
                            </td>
                            <td className="contracts-count">
                                {client.expired_agreements || 0}
                            </td>
                            <td className="contracts-count">
                                {client.archived_agreements || 0}
                            </td>
                            <td className="actions">
                                <div className="clients-table-actions">
                                    <button
                                        onClick={() => openEditModal(client)}
                                        className="clients-table-icon-button"
                                        title="Editar"
                                    >
                                        <img
                                            src={EditIcon}
                                            alt="Editar"
                                            style={{
                                                width: "26px",
                                                height: "26px",
                                                filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                            }}
                                        />
                                    </button>
                                    <button
                                        onClick={() =>
                                            openSubEntitiesPanel(client)
                                        }
                                        className="clients-table-icon-button"
                                        title="Filiais/Dependentes"
                                    >
                                        <img
                                            src={BranchIcon}
                                            alt="Filiais"
                                            style={{
                                                width: "26px",
                                                height: "26px",
                                                color: "#9b59b6",
                                            }}
                                        />
                                    </button>
                                    {isArchived ? (
                                        <button
                                            onClick={() =>
                                                unarchiveEntity(client.id)
                                            }
                                            className="clients-table-icon-button"
                                            title="Desarquivar"
                                        >
                                            <img
                                                src={UnarchiveIcon}
                                                alt="Desarquivar"
                                                style={{
                                                    width: "26px",
                                                    height: "26px",
                                                    filter: "invert(62%) sepia(34%) saturate(760%) hue-rotate(88deg) brightness(93%) contrast(81%)",
                                                }}
                                            />
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() =>
                                                archiveEntity(client.id)
                                            }
                                            className="clients-table-icon-button"
                                            title="Arquivar"
                                        >
                                            <img
                                                src={ArchiveIcon}
                                                alt="Arquivar"
                                                style={{
                                                    width: "26px",
                                                    height: "26px",
                                                    filter: "invert(64%) sepia(81%) saturate(455%) hue-rotate(359deg) brightness(98%) contrast(91%)",
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
