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
import "./CategoryModal.css";

export default function CategoryModal({
    showModal,
    modalMode,
    categoryForm,
    setCategoryForm,
    onSubmit,
    onClose,
    error,
}) {
    if (!showModal) return null;

    return (
        <div className="category-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="category-modal-content"
            >
                <h2 className="category-modal-title">
                    {modalMode === "create"
                        ? "Nova Categoria"
                        : "Editar Categoria"}
                </h2>

                <form onSubmit={onSubmit}>
                    <div className="category-modal-form-group">
                        <label className="category-modal-label">
                            Nome da Categoria *
                        </label>
                        <input
                            type="text"
                            value={categoryForm.name}
                            onChange={(e) =>
                                setCategoryForm({
                                    ...categoryForm,
                                    name: e.target.value,
                                })
                            }
                            required
                            className="category-modal-input"
                        />
                    </div>

                    {error && (
                        <div className="category-modal-error">{error}</div>
                    )}

                    <div className="category-modal-button-group">
                        <button
                            type="button"
                            onClick={onClose}
                            className="category-modal-button category-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="category-modal-button category-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
