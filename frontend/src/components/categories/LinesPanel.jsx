import React from "react";

export default function LinesPanel({
    selectedCategory,
    lines,
    onCreateLine,
    onEditLine,
    onDeleteLine,
}) {
    if (!selectedCategory) {
        return (
            <div
                style={{
                    background: "white",
                    borderRadius: "8px",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                    border: "1px solid #ecf0f1",
                    padding: "40px",
                    marginTop: "20px",
                    textAlign: "center",
                }}
            >
                <p style={{ fontSize: "16px", color: "#7f8c8d" }}>
                    Selecione uma categoria para ver suas linhas
                </p>
            </div>
        );
    }

    return (
        <div
            style={{
                background: "white",
                borderRadius: "8px",
                boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                border: "1px solid #ecf0f1",
                padding: "24px",
                marginTop: "20px",
            }}
        >
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "20px",
                }}
            >
                <h2
                    style={{
                        margin: 0,
                        fontSize: "20px",
                        color: "#2c3e50",
                    }}
                >
                    Linhas de {selectedCategory.name}
                </h2>
                <button
                    onClick={onCreateLine}
                    style={{
                        padding: "8px 16px",
                        background: "#27ae60",
                        color: "white",
                        border: "none",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                        fontWeight: "600",
                    }}
                >
                    + Nova Linha
                </button>
            </div>

            {lines.length === 0 ? (
                <div
                    style={{
                        padding: "40px",
                        textAlign: "center",
                        color: "#7f8c8d",
                    }}
                >
                    <p style={{ fontSize: "14px", margin: 0 }}>
                        Nenhuma linha cadastrada para esta categoria
                    </p>
                </div>
            ) : (
                <div
                    style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "12px",
                    }}
                >
                    {lines.map((line) => (
                        <div
                            key={line.id}
                            style={{
                                padding: "16px",
                                border: "1px solid #ecf0f1",
                                borderRadius: "6px",
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                            }}
                        >
                            <span
                                style={{
                                    fontSize: "14px",
                                    color: "#2c3e50",
                                }}
                            >
                                {line.line}
                            </span>
                            <div style={{ display: "flex", gap: "8px" }}>
                                <button
                                    onClick={() => onEditLine(line)}
                                    style={{
                                        padding: "6px 12px",
                                        background: "#3498db",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "13px",
                                    }}
                                >
                                    Editar
                                </button>
                                <button
                                    onClick={() => onDeleteLine(line.id, line.line)}
                                    style={{
                                        padding: "6px 12px",
                                        background: "#e74c3c",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "13px",
                                    }}
                                >
                                    Deletar
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
