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
import "./ClientModal.css";

export default function ClientModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    handleSubmit,
    closeModal,
    error,
}) {
    const [localError, setLocalError] = useState("");

    if (!showModal) return null;

    const formatCPFCNPJ = (value) => {
        // Remove tudo que não é dígito
        const numbers = value.replace(/\D/g, "");

        if (numbers.length <= 11) {
            // Formata CPF: 000.000.000-00
            return numbers
                .replace(/(\d{3})(\d)/, "$1.$2")
                .replace(/(\d{3})(\d)/, "$1.$2")
                .replace(/(\d{3})(\d{1,2})$/, "$1-$2");
        } else {
            // Formata CNPJ: 00.000.000/0000-00
            return numbers
                .replace(/(\d{2})(\d)/, "$1.$2")
                .replace(/(\d{3})(\d)/, "$1.$2")
                .replace(/(\d{3})(\d)/, "$1/$2")
                .replace(/(\d{4})(\d{1,2})$/, "$1-$2");
        }
    };

    const handleCPFCNPJChange = (e) => {
        const formatted = formatCPFCNPJ(e.target.value);
        setFormData({
            ...formData,
            registration_id: formatted,
        });
    };

    const formatDateToInput = (dateString) => {
        if (!dateString) return "";
        // Se já está no formato yyyy-mm-dd, retorna
        if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
            return dateString;
        }
        // Se está no formato dd/mm/yyyy, converte para yyyy-mm-dd
        if (dateString.match(/^\d{2}\/\d{2}\/\d{4}$/)) {
            const [day, month, year] = dateString.split("/");
            return `${year}-${month}-${day}`;
        }
        return dateString;
    };

    const formatDateToDisplay = (dateString) => {
        if (!dateString) return "";
        // Se está no formato yyyy-mm-dd, converte para dd/mm/yyyy
        if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
            const [year, month, day] = dateString.split("-");
            return `${day}/${month}/${year}`;
        }
        return dateString;
    };

    const handleFormSubmit = async (e) => {
        e.preventDefault();
        setLocalError("");
        try {
            await handleSubmit(e);
            setLocalError("");
        } catch (err) {
            setLocalError(err.message || "Erro ao salvar cliente");
        }
    };

    return (
        <div className="client-modal-overlay" onClick={closeModal}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="client-modal-content"
            >
                <h2 className="client-modal-title">
                    {modalMode === "create" ? "Novo Cliente" : "Editar Cliente"}
                </h2>

                <form onSubmit={handleFormSubmit}>
                    <div className="client-modal-form-group">
                        <label className="client-modal-label">Nome *</label>
                        <input
                            type="text"
                            value={formData.name}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    name: e.target.value,
                                })
                            }
                            required
                            className="client-modal-input"
                        />
                    </div>

                    <div className="client-modal-form-row">
                        <div className="client-modal-form-group">
                            <label className="client-modal-label">
                                CPF/CNPJ
                            </label>
                            <input
                                type="text"
                                value={formData.registration_id}
                                onChange={handleCPFCNPJChange}
                                placeholder="000.000.000-00 ou 00.000.000/0000-00"
                                maxLength="18"
                                className="client-modal-input"
                            />
                        </div>

                        <div className="client-modal-form-group">
                            <label className="client-modal-label">
                                Apelido/Nome Fantasia
                            </label>
                            <input
                                type="text"
                                value={formData.nickname}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        nickname: e.target.value,
                                    })
                                }
                                className="client-modal-input"
                            />
                        </div>
                    </div>

                    <div className="client-modal-form-group">
                        <label className="client-modal-label">
                            Data de Nascimento
                        </label>
                        <input
                            type="date"
                            value={formatDateToInput(formData.birth_date)}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    birth_date: e.target.value,
                                })
                            }
                            className="client-modal-input"
                        />
                    </div>

                    <div className="client-modal-form-row">
                        <div className="client-modal-form-group">
                            <label className="client-modal-label">Email</label>
                            <input
                                type="email"
                                value={formData.email}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        email: e.target.value,
                                    })
                                }
                                className="client-modal-input"
                            />
                        </div>

                        <div className="client-modal-form-group">
                            <label className="client-modal-label">
                                Telefone
                            </label>
                            <input
                                type="text"
                                value={formData.phone}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        phone: e.target.value,
                                    })
                                }
                                placeholder="(00) 00000-0000"
                                className="client-modal-input"
                            />
                        </div>
                    </div>

                    <div className="client-modal-form-group">
                        <label className="client-modal-label">Endereço</label>
                        <input
                            type="text"
                            value={formData.address}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    address: e.target.value,
                                })
                            }
                            className="client-modal-input"
                        />
                    </div>

                    <div className="client-modal-form-group">
                        <label className="client-modal-label">
                            Preferência de Contato
                        </label>
                        <select
                            value={formData.contact_preference}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    contact_preference: e.target.value,
                                })
                            }
                            className="client-modal-input"
                        >
                            <option value="">Selecione...</option>
                            <option value="email">Email</option>
                            <option value="phone">Telefone</option>
                            <option value="whatsapp">WhatsApp</option>
                        </select>
                    </div>

                    <div className="client-modal-form-group">
                        <label className="client-modal-label">Tags</label>
                        <input
                            type="text"
                            value={formData.tags}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    tags: e.target.value,
                                })
                            }
                            placeholder="Separadas por vírgula"
                            className="client-modal-input"
                        />
                    </div>

                    <div className="client-modal-form-group">
                        <label className="client-modal-label">
                            Observações
                        </label>
                        <textarea
                            value={formData.notes}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    notes: e.target.value,
                                })
                            }
                            rows="4"
                            className="client-modal-textarea"
                        />
                    </div>

                    {(error || localError) && (
                        <div className="client-modal-error">
                            {error || localError}
                        </div>
                    )}

                    <div className="client-modal-button-group">
                        <button
                            type="button"
                            onClick={closeModal}
                            className="client-modal-button client-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="client-modal-button client-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
