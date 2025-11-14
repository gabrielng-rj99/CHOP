import React from "react";
import "./UserModal.css";

export default function UserModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    onSubmit,
    onClose,
}) {
    if (!showModal) return null;

    return (
        <div className="user-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="user-modal-content"
            >
                <h2 className="user-modal-title">
                    {modalMode === "create" ? "Novo Usuário" : "Editar Usuário"}
                </h2>

                <form onSubmit={onSubmit}>
                    {/* Username */}
                    <div className="user-modal-form-group">
                        <label className="user-modal-label">
                            Nome de Usuário *
                        </label>
                        <input
                            type="text"
                            value={formData.username}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    username: e.target.value,
                                })
                            }
                            required
                            disabled={modalMode === "edit"}
                            className="user-modal-input"
                        />
                        {modalMode === "edit" && (
                            <small className="user-modal-hint">
                                Nome de usuário não pode ser alterado
                            </small>
                        )}
                    </div>

                    {/* Display Name */}
                    <div className="user-modal-form-group">
                        <label className="user-modal-label">
                            Nome de Exibição *
                        </label>
                        <input
                            type="text"
                            value={formData.display_name}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    display_name: e.target.value,
                                })
                            }
                            required
                            className="user-modal-input"
                        />
                    </div>

                    {/* Password */}
                    <div className="user-modal-form-group">
                        <label className="user-modal-label">
                            Senha{" "}
                            {modalMode === "create"
                                ? "*"
                                : "(deixe em branco para manter)"}
                        </label>
                        <input
                            type="password"
                            value={formData.password}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    password: e.target.value,
                                })
                            }
                            required={modalMode === "create"}
                            placeholder={
                                modalMode === "edit"
                                    ? "Digite apenas se quiser alterar"
                                    : ""
                            }
                            className="user-modal-input"
                        />
                    </div>

                    {/* Role */}
                    <div className="user-modal-form-group">
                        <label className="user-modal-label">Função *</label>
                        <select
                            value={formData.role}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    role: e.target.value,
                                })
                            }
                            required
                            className="user-modal-select"
                            data-role={formData.role}
                        >
                            <option value="user" className="user-modal-option">
                                Usuário
                            </option>
                            <option value="admin" className="user-modal-option">
                                Administrador
                            </option>
                            <option
                                value="full_admin"
                                className="user-modal-option user-modal-option-full-admin"
                            >
                                Administrador Total
                            </option>
                        </select>
                    </div>

                    <div className="user-modal-button-group">
                        <button
                            type="button"
                            onClick={onClose}
                            className="user-modal-button user-modal-button-cancel"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            className="user-modal-button user-modal-button-submit"
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
