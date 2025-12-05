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
import "./CategoriesTable.css";
import BoxOpenIcon from "../../assets/icons/box-open.svg";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";

export default function CategoriesTable({
    filteredCategories,
    onSelectCategory,
    onEditCategory,
    onDeleteCategory,
    onArchiveCategory,
    onUnarchiveCategory,
    selectedCategory,
}) {
    if (filteredCategories.length === 0) {
        return (
            <div className="categories-table-empty">
                <p>Nenhuma categoria encontrada</p>
            </div>
        );
    }

    return (
        <table className="categories-table">
            <thead>
                <tr>
                    <th>Nome da Categoria</th>
                    <th>Status</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredCategories.map((category) => {
                    const isArchived = !!category.archived_at;
                    return (
                        <tr
                            key={category.id}
                            className={
                                selectedCategory?.id === category.id
                                    ? "selected"
                                    : ""
                            }
                        >
                            <td>{category.name}</td>
                            <td>
                                <span
                                    className={`categories-table-status ${isArchived ? "archived" : "active"}`}
                                    style={{
                                        background: isArchived
                                            ? "#95a5a620"
                                            : "#27ae6020",
                                        color: isArchived
                                            ? "#95a5a6"
                                            : "#27ae60",
                                        padding: "4px 12px",
                                        borderRadius: "12px",
                                        fontSize: "12px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {isArchived ? "Arquivado" : "Ativo"}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="categories-table-actions">
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onEditCategory(category);
                                        }}
                                        className="categories-table-icon-button"
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
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onSelectCategory(category);
                                        }}
                                        className="categories-table-icon-button"
                                        title="Ver Linhas"
                                    >
                                        <img
                                            src={BoxOpenIcon}
                                            alt="Ver Linhas"
                                            style={{
                                                width: "26px",
                                                height: "26px",
                                                color: "#9b59b6",
                                            }}
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
                                                style={{
                                                    width: "26px",
                                                    height: "26px",
                                                    filter: "invert(62%) sepia(34%) saturate(760%) hue-rotate(88deg) brightness(93%) contrast(81%)",
                                                }}
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
                                                style={{
                                                    width: "26px",
                                                    height: "26px",
                                                    filter: "invert(64%) sepia(81%) saturate(455%) hue-rotate(359deg) brightness(98%) contrast(91%)",
                                                }}
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
                                            style={{
                                                width: "26px",
                                                height: "26px",
                                                filter: "invert(37%) sepia(93%) saturate(1447%) hue-rotate(342deg) brightness(94%) contrast(88%)",
                                            }}
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
