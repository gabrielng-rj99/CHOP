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
import { useNavigate } from "react-router-dom";
import "./CategoriesTable.css";
import TrashIcon from "../../assets/icons/trash.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";
import ContractIcon from "../../assets/icons/contract.svg";
import { useConfig } from "../../contexts/ConfigContext";

export default function CategoriesTable({
    filteredCategories,
    onSelectCategory,
    onDeleteCategory,
    onArchiveCategory,
    onUnarchiveCategory,
    selectedCategory,
}) {
    const { config } = useConfig();
    const { labels } = config;
    const navigate = useNavigate();

    const handleViewContracts = (e, categoryId) => {
        e.stopPropagation();
        navigate(`/contracts?categoryId=${categoryId}`);
    };

    if (filteredCategories.length === 0) {
        return (
            <div className="categories-table-empty">
                <p>
                    Nenhuma {labels.category?.toLowerCase() || "categoria"}{" "}
                    encontrada
                </p>
            </div>
        );
    }

    return (
        <table className="categories-table">
            <thead>
                <tr>
                    <th>Nome da {labels.category || "Categoria"}</th>
                    <th>Status</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredCategories.map((category) => {
                    const isArchived = !!category.archived_at;
                    const isSelected = selectedCategory?.id === category.id;
                    return (
                        <tr
                            key={category.id}
                            className={`categories-table-row ${isSelected ? "selected" : ""}`}
                            onClick={() => onSelectCategory(category)}
                        >
                            <td className="categories-table-name">
                                {category.name}
                            </td>
                            <td className="categories-table-status-cell">
                                <span
                                    className={`categories-table-status ${isArchived ? "archived" : "active"}`}
                                >
                                    {isArchived ? "Arquivado" : "Ativo"}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="categories-table-actions">
                                    <button
                                        onClick={(e) =>
                                            handleViewContracts(e, category.id)
                                        }
                                        className="categories-table-icon-button"
                                        title={`Ver ${labels.contracts?.toLowerCase() || "contratos"} desta ${labels.category?.toLowerCase() || "categoria"}`}
                                    >
                                        <img
                                            src={ContractIcon}
                                            alt="Ver contratos"
                                            className="categories-table-icon contract-icon"
                                        />
                                    </button>
                                    {isArchived ? (
                                        <button
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onUnarchiveCategory(
                                                    category.id,
                                                    category.name,
                                                );
                                            }}
                                            className="categories-table-icon-button"
                                            title="Desarquivar"
                                        >
                                            <img
                                                src={UnarchiveIcon}
                                                alt="Desarquivar"
                                                className="categories-table-icon unarchive-icon"
                                            />
                                        </button>
                                    ) : (
                                        <button
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onArchiveCategory(
                                                    category.id,
                                                    category.name,
                                                );
                                            }}
                                            className="categories-table-icon-button"
                                            title="Arquivar"
                                        >
                                            <img
                                                src={ArchiveIcon}
                                                alt="Arquivar"
                                                className="categories-table-icon archive-icon"
                                            />
                                        </button>
                                    )}
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onDeleteCategory(
                                                category.id,
                                                category.name,
                                            );
                                        }}
                                        className="categories-table-icon-button"
                                        title="Deletar"
                                    >
                                        <img
                                            src={TrashIcon}
                                            alt="Deletar"
                                            className="categories-table-icon delete-icon"
                                        />
                                    </button>
                                </div>
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
