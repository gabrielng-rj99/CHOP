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
