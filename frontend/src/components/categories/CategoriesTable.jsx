import React from "react";
import "./CategoriesTable.css";

export default function CategoriesTable({
    filteredCategories,
    onSelectCategory,
    onEditCategory,
    onDeleteCategory,
    selectedCategory,
}) {
    if (filteredCategories.length === 0) {
        return (
            <div className="categories-table-empty">
                <p>Nenhuma categoria encontrada</p>
            </div>
        );
    }

    return (
        <table className="categories-table">
            <thead>
                <tr>
                    <th>Nome da Categoria</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredCategories.map((category) => (
                    <tr
                        key={category.id}
                        className={
                            selectedCategory?.id === category.id
                                ? "selected"
                                : ""
                        }
                    >
                        <td>{category.name}</td>
                        <td className="actions">
                            <div className="categories-table-actions">
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onEditCategory(category);
                                    }}
                                    className="categories-table-icon-button"
                                    title="Editar"
                                >
                                    <svg
                                        width="22"
                                        height="22"
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="#3498db"
                                        strokeWidth="2"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                    >
                                        <path d="M12 20h9" />
                                        <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z" />
                                    </svg>
                                </button>
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onSelectCategory(category);
                                    }}
                                    className="categories-table-icon-button"
                                    title="Ver Linhas"
                                >
                                    <i
                                        className="fa-light fa-box-open"
                                        style={{
                                            fontSize: "18px",
                                            color: "#9b59b6",
                                        }}
                                    ></i>
                                </button>
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onDeleteCategory(
                                            category.id,
                                            category.name,
                                        );
                                    }}
                                    className="categories-table-icon-button"
                                    title="Deletar"
                                >
                                    <svg
                                        width="22"
                                        height="22"
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="#e74c3c"
                                        strokeWidth="2"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                    >
                                        <polyline points="3 6 5 6 21 6"></polyline>
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m5 0V4a2 2 0 0 1 2-2h0a2 2 0 0 1 2 2v2"></path>
                                        <line
                                            x1="10"
                                            y1="11"
                                            x2="10"
                                            y2="17"
                                        ></line>
                                        <line
                                            x1="14"
                                            y1="11"
                                            x2="14"
                                            y2="17"
                                        ></line>
                                    </svg>
                                </button>
                            </div>
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}
