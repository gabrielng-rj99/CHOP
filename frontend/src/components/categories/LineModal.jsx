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
import "./LineModal.css";

export default function LineModal({
    showModal,
    modalMode,
    lineForm,
    setLineForm,
    onSubmit,
    onClose,
    error,
}) {
    if (!showModal) return null;

    return (
        <div className="line-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="line-modal-content"
            >
                <h2 className="line-modal-title">
                    {modalMode === "create" ? "Nova Linha" : "Editar Linha"}
                </h2>

                <form onSubmit={onSubmit}>
                    <div className="line-modal-form-group">
                        <label className="line-modal-label">
                            Nome da Linha *
                        </label>
                        <input
                            type="text"
                            value={lineForm.line}
                            onChange={(e) =>
                                setLineForm({
                                    ...lineForm,
                                    line: e.target.value,
                                })
                            }
                            required
                            className="line-modal-input"
                        />
                    </div>

                    {error && <div className="line-modal-error">{error}</div>}

                    <div className="line-modal-button-group">
                        <button
                            type="button"
                            onClick={onClose}
                            className="line-modal-button line-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="line-modal-button line-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
