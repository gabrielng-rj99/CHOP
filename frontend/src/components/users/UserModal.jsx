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
    currentUserRole,
}) {
    const [passwordLength, setPasswordLength] = useState(42); // valor inicial alterado para 42
    const [showPassword, setShowPassword] = useState(false);
    const [passwordCopied, setPasswordCopied] = useState(false);
    const [isPasswordFocused, setIsPasswordFocused] = useState(false);

    if (!showModal) return null;

    const generateRandomPassword = (customLength) => {
        const length = customLength ?? passwordLength;
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
        for (let i = password.length; i < length; i++) {
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

        return password;
    };

    const copyPasswordToClipboard = () => {
        if (formData.password) {
            navigator.clipboard.writeText(formData.password);
            setPasswordCopied(true);
            setTimeout(() => setPasswordCopied(false), 1500);
        }
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

                <form onSubmit={onSubmit}>
                    {/* Username & Display Name Side by Side */}
                    <div
                        className="user-modal-form-row"
                        style={{ display: "flex", gap: "16px" }}
                    >
                        <div style={{ flex: 1 }}>
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
                                disabled={
                                    modalMode === "edit" &&
                                    currentUserRole !== "root"
                                }
                                className="user-modal-input"
                                style={{ width: "100%" }}
                            />
                            {modalMode === "edit" &&
                                currentUserRole !== "root" && (
                                    <small className="user-modal-hint">
                                        Apenas usuários root podem alterar
                                        username
                                    </small>
                                )}
                        </div>
                        <div style={{ flex: 1 }}>
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
                                style={{ width: "100%" }}
                            />
                        </div>
                    </div>

                    {/* Password */}
                    <div className="user-modal-form-group">
                        <label className="user-modal-label">
                            Senha{" "}
                            {modalMode === "create"
                                ? "*"
                                : "(deixe em branco para manter)"}
                        </label>
                        <div
                            className="user-modal-password-group"
                            style={{
                                display: "flex",
                                alignItems: "center",
                                width: "100%",
                                gap: "8px",
                            }}
                        >
                            <input
                                type={showPassword ? "text" : "password"}
                                value={formData.password}
                                onChange={(e) => {
                                    let val = e.target.value.replace(/\n/g, "");
                                    if (val.length > 64) val = val.slice(0, 64);
                                    setFormData({
                                        ...formData,
                                        password: val,
                                    });
                                }}
                                maxLength={64}
                                className="user-modal-input user-modal-password-input"
                                style={{ flex: 1, minWidth: 0 }}
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
                                {showPassword ? "👁️" : "𓁹"}
                            </button>
                            <button
                                type="button"
                                onClick={copyPasswordToClipboard}
                                className="user-modal-password-toggle user-modal-password-copy"
                                title="Copiar senha"
                            >
                                📋
                            </button>
                            {passwordCopied && (
                                <span className="user-modal-password-copied">
                                    Senha copiada!
                                </span>
                            )}
                        </div>

                        {/* Password Generator */}
                        <div className="user-modal-password-generator">
                            <div className="user-modal-password-generator-header">
                                <label className="user-modal-label-small">
                                    Gerar Senha Automática
                                </label>
                                <button
                                    type="button"
                                    onClick={() => {
                                        const newPassword =
                                            generateRandomPassword(
                                                passwordLength,
                                            );
                                        setFormData({
                                            ...formData,
                                            password: newPassword,
                                        });
                                        setTimeout(() => {
                                            // Seleciona o input de senha pelo seletor de classe
                                            const passwordInput =
                                                document.querySelector(
                                                    ".user-modal-password-input",
                                                );
                                            if (passwordInput) {
                                                navigator.clipboard.writeText(
                                                    passwordInput.value,
                                                );
                                                setPasswordCopied(true);
                                                setTimeout(
                                                    () =>
                                                        setPasswordCopied(
                                                            false,
                                                        ),
                                                    1500,
                                                );
                                            }
                                        }, 100);
                                    }}
                                    className="user-modal-generate-button"
                                >
                                    🎲 Gerar e Copiar
                                </button>
                            </div>
                            <div className="user-modal-password-slider">
                                <input
                                    type="range"
                                    min="24"
                                    max="64"
                                    value={passwordLength}
                                    onChange={(e) => {
                                        const newLength = parseInt(
                                            e.target.value,
                                        );
                                        setPasswordLength(newLength);
                                        generateRandomPassword(newLength);
                                    }}
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
                                value="root"
                                className="user-modal-option user-modal-option-root"
                            >
                                Administrador Total
                            </option>
                        </select>
                    </div>

                    {error && <div className="user-modal-error">{error}</div>}

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
