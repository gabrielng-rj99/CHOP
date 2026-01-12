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

import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./LinesPanel.css";
import { useConfig } from "../../contexts/ConfigContext";
import { filterSubcategories } from "../../utils/categoryHelpers";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";
import ContractIcon from "../../assets/icons/contract.svg";

export default function LinesPanel({
    selectedCategory,
    lines,
    onCreateLine,
    onEditLine,
    onDeleteLine,
    onArchiveLine,
    onUnarchiveSubcategory,
    onEditCategory,
    onClose,
}) {
    const { config, getGenderHelpers } = useConfig();
    const { labels } = config;
    const gSub = getGenderHelpers("subcategory");
    const navigate = useNavigate();

    const handleViewContracts = (e, subcategoryId) => {
        e.stopPropagation();
        navigate(
            `/contracts?categoryId=${selectedCategory.id}&subcategoryId=${subcategoryId}`,
        );
    };
    const SUBCATEGORY_LABEL = labels.subcategories || "Subcategorias";
    const SUBCATEGORY_SINGLE = labels.subcategory || "Subcategoria";
    const NEW_SUBCATEGORY_LABEL =
        "+ " + (gSub.new || "Nova") + " " + SUBCATEGORY_SINGLE;

    // Filters and pagination state
    const [filter, setFilter] = useState("all");
    const [searchTerm, setSearchTerm] = useState("");
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(20);
    const filtersContainerRef = useRef(null);

    // Reset pagination when lines or filter changes
    useEffect(() => {
        setCurrentPage(1);
    }, [lines, filter, searchTerm]);

    // Equalize filter button widths
    useEffect(() => {
        if (filtersContainerRef.current) {
            const buttons = filtersContainerRef.current.querySelectorAll(
                ".lines-panel-filter-button",
            );
            if (buttons.length > 0) {
                buttons.forEach((btn) => (btn.style.minWidth = "auto"));
                let minButtonWidth = 0;
                buttons.forEach((btn) => {
                    const width = btn.offsetWidth;
                    if (width > minButtonWidth) {
                        minButtonWidth = width;
                    }
                });
                minButtonWidth = Math.max(minButtonWidth, 100);
                buttons.forEach((btn) => {
                    btn.style.minWidth = minButtonWidth + "px";
                });
            }
        }
    }, [filter, lines]);

    if (!selectedCategory) {
        return null;
    }

    // Filter lines
    const allFilteredLines = filterSubcategories(lines, searchTerm, filter);

    // Pagination
    const totalItems = allFilteredLines.length;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedLines = allFilteredLines.slice(startIndex, endIndex);

    // Counts for filters
    const activeCount = lines.filter((l) => !l.archived_at).length;
    const archivedCount = lines.filter((l) => !!l.archived_at).length;

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

    return (
        <>
            <div className="lines-panel-overlay" onClick={onClose}></div>
            <div className="lines-panel">
                <div className="lines-panel-header">
                    <button
                        onClick={onCreateLine}
                        className="lines-panel-new-button"
                    >
                        {NEW_SUBCATEGORY_LABEL}
                    </button>
                    <div className="lines-panel-header-center">
                        <div
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "8px",
                                justifyContent: "center",
                            }}
                        >
                            {onEditCategory && (
                                <button
                                    onClick={() =>
                                        onEditCategory(selectedCategory)
                                    }
                                    className="lines-panel-edit-category-button"
                                    title="Editar nome da categoria"
                                >
                                    ✏️
                                </button>
                            )}
                            <h2 className="lines-panel-title">
                                {SUBCATEGORY_LABEL} de {selectedCategory.name}
                            </h2>
                        </div>
                        <p className="lines-panel-subtitle">
                            {lines.length}{" "}
                            {lines.length === 1
                                ? SUBCATEGORY_SINGLE.toLowerCase()
                                : SUBCATEGORY_LABEL.toLowerCase()}
                        </p>
                    </div>
                    <button onClick={onClose} className="lines-panel-close">
                        ✕
                    </button>
                </div>

                <div className="lines-panel-content">
                    {/* Filters */}
                    <div
                        className="lines-panel-filters"
                        ref={filtersContainerRef}
                    >
                        <button
                            onClick={() => setFilter("all")}
                            className={`lines-panel-filter-button ${filter === "all" ? "active-all" : ""}`}
                        >
                            {gSub.all} ({lines.length})
                        </button>
                        <button
                            onClick={() => setFilter("active")}
                            className={`lines-panel-filter-button ${filter === "active" ? "active-active" : ""}`}
                        >
                            {gSub.active} ({activeCount})
                        </button>
                        <button
                            onClick={() => setFilter("archived")}
                            className={`lines-panel-filter-button ${filter === "archived" ? "active-archived" : ""}`}
                        >
                            {gSub.archived} ({archivedCount})
                        </button>
                    </div>

                    {/* Search */}
                    <input
                        type="text"
                        placeholder={`Buscar ${SUBCATEGORY_LABEL.toLowerCase()}...`}
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="lines-panel-search-input"
                        style={{ marginBottom: "16px" }}
                    />

                    {allFilteredLines.length === 0 ? (
                        <div className="lines-panel-no-lines">
                            <p>
                                {searchTerm || filter !== "all"
                                    ? `Nenhuma ${SUBCATEGORY_SINGLE.toLowerCase()} encontrada com os filtros atuais`
                                    : `Nenhuma ${SUBCATEGORY_SINGLE.toLowerCase()} cadastrada para esta categoria`}
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Table */}
                            <div className="lines-panel-table-wrapper">
                                <table className="lines-panel-table">
                                    <thead>
                                        <tr>
                                            <th>Nome</th>
                                            <th className="status-col">
                                                Status
                                            </th>
                                            <th className="actions-col">
                                                Ações
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {paginatedLines.map((line) => {
                                            const isArchived =
                                                !!line.archived_at;
                                            return (
                                                <tr
                                                    key={line.id}
                                                    className="lines-panel-table-row"
                                                    onClick={() =>
                                                        onEditLine(line)
                                                    }
                                                >
                                                    <td className="lines-panel-table-name">
                                                        {line.name}
                                                    </td>
                                                    <td className="lines-panel-table-status-cell">
                                                        <span
                                                            className={`lines-panel-status ${isArchived ? "archived" : "active"}`}
                                                        >
                                                            {isArchived
                                                                ? "Arquivado"
                                                                : "Ativo"}
                                                        </span>
                                                    </td>
                                                    <td className="lines-panel-table-actions">
                                                        <div className="lines-panel-actions-wrapper">
                                                            <button
                                                                onClick={(e) =>
                                                                    handleViewContracts(
                                                                        e,
                                                                        line.id,
                                                                    )
                                                                }
                                                                className="lines-panel-icon-button"
                                                                title={`Ver ${labels.contracts?.toLowerCase() || "contratos"} desta ${labels.subcategory?.toLowerCase() || "subcategoria"}`}
                                                            >
                                                                <img
                                                                    src={
                                                                        ContractIcon
                                                                    }
                                                                    alt="Ver contratos"
                                                                    className="lines-panel-icon contract-icon"
                                                                />
                                                            </button>
                                                            <button
                                                                onClick={(
                                                                    e,
                                                                ) => {
                                                                    e.stopPropagation();
                                                                    onEditLine(
                                                                        line,
                                                                    );
                                                                }}
                                                                className="lines-panel-icon-button"
                                                                title="Editar"
                                                            >
                                                                <img
                                                                    src={
                                                                        EditIcon
                                                                    }
                                                                    alt="Editar"
                                                                    className="lines-panel-icon edit-icon"
                                                                />
                                                            </button>
                                                            {isArchived ? (
                                                                <button
                                                                    onClick={(
                                                                        e,
                                                                    ) => {
                                                                        e.stopPropagation();
                                                                        onUnarchiveSubcategory(
                                                                            line.id,
                                                                            line.name,
                                                                        );
                                                                    }}
                                                                    className="lines-panel-icon-button"
                                                                    title="Desarquivar"
                                                                >
                                                                    <img
                                                                        src={
                                                                            UnarchiveIcon
                                                                        }
                                                                        alt="Desarquivar"
                                                                        className="lines-panel-icon unarchive-icon"
                                                                    />
                                                                </button>
                                                            ) : (
                                                                <button
                                                                    onClick={(
                                                                        e,
                                                                    ) => {
                                                                        e.stopPropagation();
                                                                        onArchiveLine(
                                                                            line.id,
                                                                            line.name,
                                                                        );
                                                                    }}
                                                                    className="lines-panel-icon-button"
                                                                    title="Arquivar"
                                                                >
                                                                    <img
                                                                        src={
                                                                            ArchiveIcon
                                                                        }
                                                                        alt="Arquivar"
                                                                        className="lines-panel-icon archive-icon"
                                                                    />
                                                                </button>
                                                            )}
                                                            <button
                                                                onClick={(
                                                                    e,
                                                                ) => {
                                                                    e.stopPropagation();
                                                                    onDeleteLine(
                                                                        line.id,
                                                                        line.name,
                                                                    );
                                                                }}
                                                                className="lines-panel-icon-button"
                                                                title="Deletar"
                                                            >
                                                                <img
                                                                    src={
                                                                        TrashIcon
                                                                    }
                                                                    alt="Deletar"
                                                                    className="lines-panel-icon delete-icon"
                                                                />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>

                            {/* Pagination */}
                            {totalItems > 0 && (
                                <div className="lines-panel-pagination">
                                    <div className="lines-panel-pagination-left">
                                        <label className="lines-panel-pagination-label">
                                            Itens por página:
                                            <select
                                                value={itemsPerPage}
                                                onChange={
                                                    handleItemsPerPageChange
                                                }
                                                className="lines-panel-pagination-select"
                                            >
                                                <option value="10">10</option>
                                                <option value="20">20</option>
                                                <option value="50">50</option>
                                                <option value="100">100</option>
                                            </select>
                                        </label>
                                        <span className="lines-panel-pagination-info">
                                            Mostrando {startItem} - {endItem} de{" "}
                                            {totalItems}
                                        </span>
                                    </div>

                                    <div className="lines-panel-pagination-right">
                                        <button
                                            onClick={handlePrevious}
                                            disabled={currentPage === 1}
                                            className="lines-panel-pagination-button"
                                        >
                                            ← Anterior
                                        </button>
                                        <span className="lines-panel-pagination-page-info">
                                            Página {currentPage} de{" "}
                                            {totalPages || 1}
                                        </span>
                                        <button
                                            onClick={handleNext}
                                            disabled={
                                                currentPage === totalPages ||
                                                totalPages === 0
                                            }
                                            className="lines-panel-pagination-button"
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
