/*
 * This file is part of Client Hub Open Project.
 * Copyright (C) 2025 Client Hub Contributors
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

import React, { useState, useEffect } from "react";
import { useConfig } from "../../contexts/ConfigContext";
import "./AffiliatesPanel.css";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";
import ContractIcon from "../../assets/icons/contract.svg";

export default function AffiliatesPanel({
    selectedClient,
    affiliates,
    onCreateAffiliate,
    onEditAffiliate,
    onDeleteAffiliate,
    onClose,
    onViewContracts,
}) {
    const { config } = useConfig();
    const { labels } = config;

    // Labels with fallbacks
    const affiliateLabel = labels.affiliate || "Afiliado";
    const affiliatesLabel = labels.affiliates || "Afiliados";
    const clientLabel = labels.client || "Cliente";

    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(20);
    const [searchTerm, setSearchTerm] = useState("");

    // Reset pagination when affiliates change
    useEffect(() => {
        setCurrentPage(1);
    }, [affiliates, searchTerm]);

    if (!selectedClient) {
        return null;
    }

    // Filter affiliates by search term
    const filteredAffiliates = affiliates.filter((affiliate) => {
        if (!searchTerm) return true;
        const search = searchTerm.toLowerCase();
        return (
            affiliate.name?.toLowerCase().includes(search) ||
            affiliate.relationship?.toLowerCase().includes(search) ||
            affiliate.phone?.toLowerCase().includes(search)
        );
    });

    // Pagination calculations
    const totalItems = filteredAffiliates.length;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedAffiliates = filteredAffiliates.slice(startIndex, endIndex);

    const handlePrevious = () => {
        if (currentPage > 1) {
            setCurrentPage(currentPage - 1);
        }
    };

    const handleNext = () => {
        if (currentPage < totalPages) {
            setCurrentPage(currentPage + 1);
        }
    };

    const handleItemsPerPageChange = (e) => {
        setItemsPerPage(parseInt(e.target.value));
        setCurrentPage(1);
    };

    const startItem = totalItems > 0 ? startIndex + 1 : 0;
    const endItem = Math.min(endIndex, totalItems);

    // Format date for display
    const formatDate = (dateString) => {
        if (!dateString) return "-";
        try {
            const date = new Date(dateString);
            return date.toLocaleDateString("pt-BR", {
                day: "2-digit",
                month: "2-digit",
                year: "numeric",
            });
        } catch {
            return "-";
        }
    };

    return (
        <>
            <div className="affiliates-panel-overlay" onClick={onClose}></div>
            <div className="affiliates-panel">
                <div className="affiliates-panel-header">
                    <button
                        onClick={onCreateAffiliate}
                        className="affiliates-panel-new-button"
                    >
                        + Novo {affiliateLabel}
                    </button>
                    <div className="affiliates-panel-header-center">
                        <h2 className="affiliates-panel-title">
                            {affiliatesLabel} de {selectedClient.name}
                        </h2>
                        <p className="affiliates-panel-subtitle">
                            {affiliates.length}{" "}
                            {affiliates.length === 1
                                ? affiliateLabel.toLowerCase()
                                : affiliatesLabel.toLowerCase()}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="affiliates-panel-close"
                    >
                        ✕
                    </button>
                </div>

                <div className="affiliates-panel-content">
                    {/* Search */}
                    <input
                        type="text"
                        placeholder={`Buscar ${affiliatesLabel.toLowerCase()}...`}
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="affiliates-panel-search-input"
                    />

                    {filteredAffiliates.length === 0 ? (
                        <div className="affiliates-panel-no-affiliates">
                            <p>
                                {searchTerm
                                    ? `Nenhum ${affiliateLabel.toLowerCase()} encontrado com os filtros atuais`
                                    : `Nenhum ${affiliateLabel.toLowerCase()} cadastrado para este ${clientLabel.toLowerCase()}`}
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Table */}
                            <div className="affiliates-panel-table-wrapper">
                                <table className="affiliates-panel-table">
                                    <thead>
                                        <tr>
                                            <th>Nome</th>
                                            <th>Relacionamento</th>
                                            <th>Data de Nascimento</th>
                                            <th>Contato</th>
                                            <th className="actions-col">
                                                Ações
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {paginatedAffiliates.map(
                                            (affiliate) => (
                                                <tr
                                                    key={affiliate.id}
                                                    className="affiliates-panel-table-row"
                                                    onClick={() =>
                                                        onEditAffiliate(
                                                            affiliate,
                                                        )
                                                    }
                                                >
                                                    <td className="affiliates-panel-table-name">
                                                        {affiliate.name}
                                                    </td>
                                                    <td>
                                                        {affiliate.relationship ||
                                                            "-"}
                                                    </td>
                                                    <td>
                                                        {formatDate(
                                                            affiliate.birth_date,
                                                        )}
                                                    </td>
                                                    <td>
                                                        {affiliate.phone || "-"}
                                                    </td>
                                                    <td className="affiliates-panel-table-actions">
                                                        <div className="affiliates-panel-actions-wrapper">
                                                            <button
                                                                onClick={(
                                                                    e,
                                                                ) => {
                                                                    e.stopPropagation();
                                                                    onViewContracts(
                                                                        affiliate,
                                                                    );
                                                                }}
                                                                className="affiliates-panel-icon-button"
                                                                title="Ver contratos"
                                                            >
                                                                <img
                                                                    src={
                                                                        ContractIcon
                                                                    }
                                                                    alt="Ver contratos"
                                                                    className="affiliates-panel-icon contract-icon"
                                                                />
                                                            </button>
                                                            <button
                                                                onClick={(
                                                                    e,
                                                                ) => {
                                                                    e.stopPropagation();
                                                                    onEditAffiliate(
                                                                        affiliate,
                                                                    );
                                                                }}
                                                                className="affiliates-panel-icon-button"
                                                                title="Editar"
                                                            >
                                                                <img
                                                                    src={
                                                                        EditIcon
                                                                    }
                                                                    alt="Editar"
                                                                    className="affiliates-panel-icon edit-icon"
                                                                />
                                                            </button>
                                                            <button
                                                                onClick={(
                                                                    e,
                                                                ) => {
                                                                    e.stopPropagation();
                                                                    onDeleteAffiliate(
                                                                        affiliate.id,
                                                                    );
                                                                }}
                                                                className="affiliates-panel-icon-button"
                                                                title="Deletar"
                                                            >
                                                                <img
                                                                    src={
                                                                        TrashIcon
                                                                    }
                                                                    alt="Deletar"
                                                                    className="affiliates-panel-icon delete-icon"
                                                                />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ),
                                        )}
                                    </tbody>
                                </table>
                            </div>

                            {/* Pagination */}
                            {totalItems > 0 && (
                                <div className="affiliates-panel-pagination">
                                    <div className="affiliates-panel-pagination-left">
                                        <label className="affiliates-panel-pagination-label">
                                            Itens por página:
                                            <select
                                                value={itemsPerPage}
                                                onChange={
                                                    handleItemsPerPageChange
                                                }
                                                className="affiliates-panel-pagination-select"
                                            >
                                                <option value="10">10</option>
                                                <option value="20">20</option>
                                                <option value="50">50</option>
                                                <option value="100">100</option>
                                            </select>
                                        </label>
                                        <span className="affiliates-panel-pagination-info">
                                            Mostrando {startItem} - {endItem} de{" "}
                                            {totalItems}
                                        </span>
                                    </div>

                                    <div className="affiliates-panel-pagination-right">
                                        <button
                                            onClick={handlePrevious}
                                            disabled={currentPage === 1}
                                            className="affiliates-panel-pagination-button"
                                        >
                                            ← Anterior
                                        </button>
                                        <span className="affiliates-panel-pagination-page-info">
                                            Página {currentPage} de{" "}
                                            {totalPages || 1}
                                        </span>
                                        <button
                                            onClick={handleNext}
                                            disabled={
                                                currentPage === totalPages ||
                                                totalPages === 0
                                            }
                                            className="affiliates-panel-pagination-button"
                                        >
                                            Próxima →
                                        </button>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>
        </>
    );
}
