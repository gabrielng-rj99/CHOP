import React from "react";

export default function CategoriesTable({
    filteredCategories,
    onSelectCategory,
    onEditCategory,
    onDeleteCategory,
    selectedCategory,
}) {
    if (filteredCategories.length === 0) {
        return (
            <div style={{ padding: "40px", textAlign: "center" }}>
                <p style={{ fontSize: "16px", color: "#7f8c8d" }}>
                    Nenhuma categoria encontrada
                </p>
            </div>
        );
    }

    return (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
                <tr style={{ background: "#f8f9fa", borderBottom: "2px solid #dee2e6" }}>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "left",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                        }}
                    >
                        Nome da Categoria
                    </th>
                    <th
                        style={{
                            padding: "16px",
                            textAlign: "center",
                            fontSize: "14px",
                            fontWeight: "600",
                            color: "#495057",
                            width: "200px",
                        }}
                    >
                        Ações
                    </th>
                </tr>
            </thead>
            <tbody>
                {filteredCategories.map((category) => (
                    <tr
                        key={category.id}
                        onClick={() => onSelectCategory(category)}
                        style={{
                            borderBottom: "1px solid #ecf0f1",
                            cursor: "pointer",
                            background:
                                selectedCategory?.id === category.id
                                    ? "#e3f2fd"
                                    : "transparent",
                        }}
                    >
                        <td
                            style={{
                                padding: "16px",
                                fontSize: "14px",
                                color: "#2c3e50",
                                fontWeight: "500",
                            }}
                        >
                            {category.name}
                        </td>
                        <td style={{ padding: "16px", textAlign: "center" }}>
                            <div
                                style={{
                                    display: "flex",
                                    gap: "8px",
                                    justifyContent: "center",
                                }}
                            >
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onEditCategory(category);
                                    }}
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
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onDeleteCategory(category.id, category.name);
                                    }}
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
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}
