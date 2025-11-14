import React from "react";

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
                    {modalMode === "create" ? "Nova Categoria" : "Editar Categoria"}
                </h2>

                <form onSubmit={onSubmit}>
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
