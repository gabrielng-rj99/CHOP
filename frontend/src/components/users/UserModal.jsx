import React, { useState } from "react";
import "./UserModal.css";

export default function UserModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    onSubmit,
    onClose,
    error,
}) {
    const [passwordLength, setPasswordLength] = useState(32);
    const [showPassword, setShowPassword] = useState(false);

    if (!showModal) return null;

    const generateRandomPassword = () => {
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const numbers = "0123456789";
        const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        const allChars = lowercase + uppercase + numbers + symbols;

        let password = "";

        // Garantir pelo menos um de cada tipo
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        // Preencher o resto
        for (let i = password.length; i < passwordLength; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        // Embaralhar a senha
        password = password
            .split("")
            .sort(() => Math.random() - 0.5)
            .join("");

        setFormData({
            ...formData,
            password: password,
        });
    };

    return (
        <div className="user-modal-overlay" onClick={onClose}>
            <div
                onClick={(e) => e.stopPropagation()}
                className="user-modal-content"
            >
                <h2 className="user-modal-title">
                    {modalMode === "create" ? "Novo Usuário" : "Editar Usuário"}
                </h2>

                {error && <div className="user-modal-error">{error}</div>}

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
                        <div className="user-modal-password-container">
                            <input
                                type={showPassword ? "text" : "password"}
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
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="user-modal-password-toggle"
                                title={
                                    showPassword
                                        ? "Ocultar senha"
                                        : "Mostrar senha"
                                }
                            >
                                {showPassword ? "👁️" : "👁️‍🗨️"}
                            </button>
                        </div>

                        {/* Password Generator */}
                        <div className="user-modal-password-generator">
                            <div className="user-modal-password-generator-header">
                                <label className="user-modal-label-small">
                                    Gerar Senha Automática
                                </label>
                                <button
                                    type="button"
                                    onClick={generateRandomPassword}
                                    className="user-modal-generate-button"
                                >
                                    🎲 Gerar
                                </button>
                            </div>
                            <div className="user-modal-password-slider">
                                <input
                                    type="range"
                                    min="24"
                                    max="64"
                                    value={passwordLength}
                                    onChange={(e) =>
                                        setPasswordLength(
                                            parseInt(e.target.value),
                                        )
                                    }
                                    className="user-modal-slider"
                                />
                                <span className="user-modal-slider-value">
                                    {passwordLength} caracteres
                                </span>
                            </div>
                        </div>
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
