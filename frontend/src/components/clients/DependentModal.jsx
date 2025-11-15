import React, { useState } from "react";
import "./DependentModal.css";

export default function DependentModal({
    showModal,
    modalMode,
    dependentForm,
    setDependentForm,
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
            setLocalError(err.message || "Erro ao salvar dependente");
        }
    };

    return (
        <div className="dependent-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="dependent-modal-content"
            >
                <h2 className="dependent-modal-title">
                    {modalMode === "create"
                        ? "Novo Dependente"
                        : "Editar Dependente"}
                </h2>

                <form onSubmit={handleFormSubmit}>
                    <div className="dependent-modal-form-group">
                        <label className="dependent-modal-label">Nome *</label>
                        <input
                            type="text"
                            value={dependentForm.name}
                            onChange={(e) =>
                                setDependentForm({
                                    ...dependentForm,
                                    name: e.target.value,
                                })
                            }
                            required
                            className="dependent-modal-input"
                        />
                    </div>

                    <div className="dependent-modal-form-group">
                        <label className="dependent-modal-label">
                            Relacionamento *
                        </label>
                        <input
                            type="text"
                            value={dependentForm.relationship}
                            onChange={(e) =>
                                setDependentForm({
                                    ...dependentForm,
                                    relationship: e.target.value,
                                })
                            }
                            required
                            placeholder="Ex: Filho, Cônjuge, Filial"
                            className="dependent-modal-input"
                        />
                    </div>

                    <div className="dependent-modal-form-row">
                        <div className="dependent-modal-form-group">
                            <label className="dependent-modal-label">
                                Data de Nascimento
                            </label>
                            <input
                                type="date"
                                value={dependentForm.birth_date}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        birth_date: e.target.value,
                                    })
                                }
                                className="dependent-modal-input"
                            />
                        </div>

                        <div className="dependent-modal-form-group">
                            <label className="dependent-modal-label">
                                Telefone
                            </label>
                            <input
                                type="text"
                                value={dependentForm.phone}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        phone: e.target.value,
                                    })
                                }
                                placeholder="(00) 00000-0000"
                                className="dependent-modal-input"
                            />
                        </div>
                    </div>

                    {(error || localError) && (
                        <div className="dependent-modal-error">
                            {error || localError}
                        </div>
                    )}

                    <div className="dependent-modal-button-group">
                        <button
                            type="button"
                            onClick={onClose}
                            className="dependent-modal-button dependent-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="dependent-modal-button dependent-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
