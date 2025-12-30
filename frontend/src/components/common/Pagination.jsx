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

import React from "react";
import "./Pagination.css";

export default function Pagination({
    currentPage,
    totalItems,
    itemsPerPage,
    onPageChange,
    onItemsPerPageChange,
}) {
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    const handlePrevious = () => {
        if (currentPage > 1) {
            onPageChange(currentPage - 1);
        }
    };

    const handleNext = () => {
        if (currentPage < totalPages) {
            onPageChange(currentPage + 1);
        }
    };

    const handlePageSelect = (e) => {
        onPageChange(parseInt(e.target.value));
    };

    const handleItemsPerPageChange = (e) => {
        onItemsPerPageChange(parseInt(e.target.value));
        onPageChange(1); // Reset to first page when changing items per page
    };

    if (totalItems === 0) {
        return null;
    }

    const startItem = (currentPage - 1) * itemsPerPage + 1;
    const endItem = Math.min(currentPage * itemsPerPage, totalItems);

    return (
        <div className="pagination-container">
            <div className="pagination-left">
                <label className="pagination-label">
                    Itens por página:
                    <select
                        value={itemsPerPage}
                        onChange={handleItemsPerPageChange}
                        className="pagination-select-items"
                    >
                        <option value="10">10</option>
                        <option value="20">20</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </label>
                <span className="pagination-info">
                    Mostrando {startItem} - {endItem} de {totalItems} itens
                </span>
            </div>

            <div className="pagination-right">
                <button
                    onClick={handlePrevious}
                    disabled={currentPage === 1}
                    className="pagination-button"
                >
                    ← Anterior
                </button>

                <span className="pagination-page-info">
                    Página {currentPage} de {totalPages}
                </span>

                <button
                    onClick={handleNext}
                    disabled={currentPage === totalPages}
                    className="pagination-button"
                >
                    Próxima →
                </button>

                <span className="pagination-separator">|</span>

                <select
                    value={currentPage}
                    onChange={handlePageSelect}
                    className="pagination-select-page"
                >
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(
                        (page) => (
                            <option key={page} value={page}>
                                Ir para página {page}
                            </option>
                        ),
                    )}
                </select>
            </div>
        </div>
    );
}
