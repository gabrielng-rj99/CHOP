import React from "react";
import "./CategoryModal.css";

export default function CategoryModal({
    showModal,
    modalMode,
    categoryForm,
    setCategoryForm,
    onSubmit,
    onClose,
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
