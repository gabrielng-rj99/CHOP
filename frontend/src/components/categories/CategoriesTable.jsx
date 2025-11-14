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
                        onClick={() => onSelectCategory(category)}
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
                                    className="categories-table-button categories-table-button-edit"
                                >
                                    Editar
                                </button>
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onDeleteCategory(
                                            category.id,
                                            category.name,
                                        );
                                    }}
                                    className="categories-table-button categories-table-button-delete"
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
