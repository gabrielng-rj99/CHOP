import React from "react";

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
        <div
            style={{
                position: "fixed",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: "rgba(0,0,0,0.5)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 1000,
            }}
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: "white",
                    borderRadius: "8px",
                    padding: "24px",
                    width: "90%",
                    maxWidth: "500px",
                }}
            >
                <h2
                    style={{
                        marginTop: 0,
                        marginBottom: "24px",
                        fontSize: "24px",
                        color: "#2c3e50",
                    }}
                >
                    {modalMode === "create" ? "Novo Usuário" : "Editar Usuário"}
                </h2>

                <form onSubmit={onSubmit}>
                    {/* Username */}
                    <div style={{ marginBottom: "20px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "8px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#495057",
                            }}
                        >
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
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ced4da",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                                opacity: modalMode === "edit" ? 0.6 : 1,
                                cursor: modalMode === "edit" ? "not-allowed" : "text",
                            }}
                        />
                        {modalMode === "edit" && (
                            <small style={{ color: "#7f8c8d", fontSize: "12px" }}>
                                Nome de usuário não pode ser alterado
                            </small>
                        )}
                    </div>

                    {/* Display Name */}
                    <div style={{ marginBottom: "20px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "8px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#495057",
                            }}
                        >
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
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ced4da",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    {/* Password */}
                    <div style={{ marginBottom: "20px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "8px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#495057",
                            }}
                        >
                            Senha {modalMode === "create" ? "*" : "(deixe em branco para manter)"}
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
                            placeholder={modalMode === "edit" ? "Digite apenas se quiser alterar" : ""}
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ced4da",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    {/* Role */}
                    <div style={{ marginBottom: "20px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "8px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#495057",
                            }}
                        >
                            Função *
                        </label>
                        <select
                            value={formData.role}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    role: e.target.value,
                                })
                            }
                            required
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ced4da",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        >
                            <option value="user">Usuário</option>
                            <option value="admin">Administrador</option>
                        </select>
                    </div>

                    <div
                        style={{
                            display: "flex",
                            gap: "12px",
                            justifyContent: "flex-end",
                        }}
                    >
                        <button
                            type="button"
                            onClick={onClose}
                            style={{
                                padding: "10px 20px",
                                background: "#95a5a6",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                            }}
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            style={{
                                padding: "10px 20px",
                                background: "#27ae60",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                                fontWeight: "600",
                            }}
                        >
                            {modalMode === "create" ? "Criar" : "Salvar"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
