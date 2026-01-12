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

import React, { useState } from "react";
import "./AffiliateModal.css";

export default function AffiliateModal({
    showModal,
    modalMode,
    affiliateForm,
    setAffiliateForm,
    onSubmit,
    onClose,
    error,
}) {
    const [localError, setLocalError] = useState("");
    if (!showModal) return null;

    const handleFormSubmit = async (e) => {
        e.preventDefault();
        setLocalError("");
        try {
            await onSubmit(e);
            setLocalError("");
        } catch (err) {
            setLocalError(err.message || "Erro ao salvar afiliado");
        }
    };

    return (
        <div className="affiliate-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="affiliate-modal-content"
            >
                <h2 className="affiliate-modal-title">
                    {modalMode === "create"
                        ? "Novo Afiliado"
                        : "Editar Afiliado"}
                </h2>

                <form onSubmit={handleFormSubmit}>
                    <div className="affiliate-modal-form-group">
                        <label className="affiliate-modal-label">Nome *</label>
                        <input
                            type="text"
                            value={affiliateForm.name}
                            onChange={(e) =>
                                setAffiliateForm({
                                    ...affiliateForm,
                                    name: e.target.value,
                                })
                            }
                            required
                            className="affiliate-modal-input"
                        />
                    </div>

                    <div className="affiliate-modal-form-group">
                        <label className="affiliate-modal-label">
                            Relacionamento
                            <span
                                style={{
                                    fontSize: "12px",
                                    color: "#7f8c8d",
                                    marginLeft: "4px",
                                    fontWeight: "normal",
                                }}
                            >
                                (opcional)
                            </span>
                        </label>
                        <input
                            type="text"
                            value={affiliateForm.relationship}
                            onChange={(e) =>
                                setAffiliateForm({
                                    ...affiliateForm,
                                    relationship: e.target.value,
                                })
                            }
                            placeholder="Ex: Filho, Cônjuge, Filial"
                            className="affiliate-modal-input"
                        />
                    </div>

                    <div className="affiliate-modal-form-row">
                        <div className="affiliate-modal-form-group">
                            <label className="affiliate-modal-label">
                                Data de Nascimento
                            </label>
                            <input
                                type="date"
                                value={affiliateForm.birth_date}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
                                        birth_date: e.target.value,
                                    })
                                }
                                className="affiliate-modal-input"
                            />
                        </div>

                        <div className="affiliate-modal-form-group">
                            <label className="affiliate-modal-label">
                                Telefone
                            </label>
                            <input
                                type="text"
                                value={affiliateForm.phone}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
                                        phone: e.target.value,
                                    })
                                }
                                placeholder="(00) 00000-0000"
                                className="affiliate-modal-input"
                            />
                        </div>
                    </div>

                    {(error || localError) && (
                        <div className="affiliate-modal-error">
                            {error || localError}
                        </div>
                    )}

                    <div className="affiliate-modal-button-group">
                        <button
                            type="button"
                            onClick={onClose}
                            className="affiliate-modal-button affiliate-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="affiliate-modal-button affiliate-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
