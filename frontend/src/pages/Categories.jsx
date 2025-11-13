import React, { useState, useEffect } from "react";

export default function Categories({ token, apiUrl }) {
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [selectedCategory, setSelectedCategory] = useState(null);
    const [showCategoryModal, setShowCategoryModal] = useState(false);
    const [showLineModal, setShowLineModal] = useState(false);
    const [categoryMode, setCategoryMode] = useState("create");
    const [lineMode, setLineMode] = useState("create");
    const [selectedLine, setSelectedLine] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [categoryForm, setCategoryForm] = useState({
        name: "",
    });
    const [lineForm, setLineForm] = useState({
        line: "",
    });

    useEffect(() => {
        loadCategories();
    }, []);

    const loadCategories = async () => {
        setLoading(true);
        setError("");

        try {
            const response = await fetch(`${apiUrl}/api/categories`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            });

            if (!response.ok) {
                throw new Error("Erro ao carregar categorias");
            }

            const data = await response.json();
            setCategories(data.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const loadLines = async (categoryId) => {
        try {
            const response = await fetch(
                `${apiUrl}/api/categories/${categoryId}/lines`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                },
            );

            if (!response.ok) {
                throw new Error("Erro ao carregar linhas");
            }

            const data = await response.json();
            setLines(data.data || []);
        } catch (err) {
            setError(err.message);
        }
    };

    const createCategory = async () => {
        try {
            const response = await fetch(`${apiUrl}/api/categories`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(categoryForm),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao criar categoria");
            }

            await loadCategories();
            closeCategoryModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateCategory = async () => {
        try {
            const response = await fetch(
                `${apiUrl}/api/categories/${selectedCategory.id}`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(categoryForm),
                },
            );

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(
                    errorData.error || "Erro ao atualizar categoria",
                );
            }

            await loadCategories();
            closeCategoryModal();
            // Reload selected category
            if (selectedCategory) {
                const updated = categories.find(
                    (c) => c.id === selectedCategory.id,
                );
                if (updated) {
                    setSelectedCategory({
                        ...updated,
                        name: categoryForm.name,
                    });
                }
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const deleteCategory = async (categoryId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja deletar a categoria "${categoryName}"?\n\nIsso pode afetar contratos vinculados a esta categoria.`,
            )
        )
            return;

        try {
            const response = await fetch(
                `${apiUrl}/api/categories/${categoryId}`,
                {
                    method: "DELETE",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                },
            );

            if (!response.ok) {
                throw new Error("Erro ao deletar categoria");
            }

            await loadCategories();
            if (selectedCategory?.id === categoryId) {
                setSelectedCategory(null);
                setLines([]);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const createLine = async () => {
        try {
            const payload = {
                line: lineForm.line,
                category_id: selectedCategory.id,
            };

            const response = await fetch(`${apiUrl}/api/lines`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao criar linha");
            }

            await loadLines(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateLine = async () => {
        try {
            const response = await fetch(
                `${apiUrl}/api/lines/${selectedLine.id}`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(lineForm),
                },
            );

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao atualizar linha");
            }

            await loadLines(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const deleteLine = async (lineId, lineName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja deletar a linha "${lineName}"?\n\nIsso pode afetar contratos vinculados a esta linha.`,
            )
        )
            return;

        try {
            const response = await fetch(`${apiUrl}/api/lines/${lineId}`, {
                method: "DELETE",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            });

            if (!response.ok) {
                throw new Error("Erro ao deletar linha");
            }

            await loadLines(selectedCategory.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateCategoryModal = () => {
        setCategoryMode("create");
        setCategoryForm({ name: "" });
        setShowCategoryModal(true);
    };

    const openEditCategoryModal = (category) => {
        setCategoryMode("edit");
        setSelectedCategory(category);
        setCategoryForm({ name: category.name });
        setShowCategoryModal(true);
    };

    const closeCategoryModal = () => {
        setShowCategoryModal(false);
        setCategoryForm({ name: "" });
        setError("");
    };

    const openCreateLineModal = () => {
        setLineMode("create");
        setSelectedLine(null);
        setLineForm({ line: "" });
        setShowLineModal(true);
    };

    const openEditLineModal = (line) => {
        setLineMode("edit");
        setSelectedLine(line);
        setLineForm({ line: line.line });
        setShowLineModal(true);
    };

    const closeLineModal = () => {
        setShowLineModal(false);
        setSelectedLine(null);
        setLineForm({ line: "" });
        setError("");
    };

    const handleCategorySubmit = (e) => {
        e.preventDefault();
        if (categoryMode === "create") {
            createCategory();
        } else {
            updateCategory();
        }
    };

    const handleLineSubmit = (e) => {
        e.preventDefault();
        if (lineMode === "create") {
            createLine();
        } else {
            updateLine();
        }
    };

    const selectCategory = async (category) => {
        setSelectedCategory(category);
        await loadLines(category.id);
    };

    const filteredCategories = categories.filter((category) =>
        searchTerm === ""
            ? true
            : category.name?.toLowerCase().includes(searchTerm.toLowerCase()),
    );

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "60px" }}>
                <div style={{ fontSize: "18px", color: "#7f8c8d" }}>
                    Carregando categorias...
                </div>
            </div>
        );
    }

    return (
        <div>
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "30px",
                }}
            >
                <h1 style={{ fontSize: "32px", color: "#2c3e50", margin: 0 }}>
                    {selectedCategory
                        ? `${selectedCategory.name} - Linhas`
                        : "Categorias"}
                </h1>
                <div style={{ display: "flex", gap: "12px" }}>
                    {selectedCategory && (
                        <button
                            onClick={() => {
                                setSelectedCategory(null);
                                setLines([]);
                            }}
                            style={{
                                padding: "10px 20px",
                                background: "white",
                                color: "#7f8c8d",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                            }}
                        >
                            ← Voltar
                        </button>
                    )}
                    <button
                        onClick={loadCategories}
                        style={{
                            padding: "10px 20px",
                            background: "white",
                            color: "#3498db",
                            border: "1px solid #3498db",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                        }}
                    >
                        Atualizar
                    </button>
                    {!selectedCategory ? (
                        <button
                            onClick={openCreateCategoryModal}
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
                            + Nova Categoria
                        </button>
                    ) : (
                        <button
                            onClick={openCreateLineModal}
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
                            + Nova Linha
                        </button>
                    )}
                </div>
            </div>

            {error && (
                <div
                    style={{
                        background: "#fee",
                        color: "#c33",
                        padding: "16px",
                        borderRadius: "4px",
                        border: "1px solid #fcc",
                        marginBottom: "20px",
                    }}
                >
                    {error}
                </div>
            )}

            {!selectedCategory ? (
                <>
                    <div style={{ marginBottom: "24px" }}>
                        <input
                            type="text"
                            placeholder="Buscar categorias..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            style={{
                                width: "100%",
                                maxWidth: "400px",
                                padding: "10px 16px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                            }}
                        />
                    </div>

                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                            border: "1px solid #ecf0f1",
                            overflow: "hidden",
                        }}
                    >
                        {filteredCategories.length === 0 ? (
                            <div
                                style={{
                                    padding: "40px",
                                    textAlign: "center",
                                    color: "#7f8c8d",
                                }}
                            >
                                Nenhuma categoria encontrada
                            </div>
                        ) : (
                            <table
                                style={{
                                    width: "100%",
                                    borderCollapse: "collapse",
                                }}
                            >
                                <thead>
                                    <tr
                                        style={{
                                            background: "#f8f9fa",
                                            borderBottom: "2px solid #ecf0f1",
                                        }}
                                    >
                                        <th
                                            style={{
                                                padding: "16px",
                                                textAlign: "left",
                                                fontSize: "13px",
                                                fontWeight: "600",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            NOME
                                        </th>
                                        <th
                                            style={{
                                                padding: "16px",
                                                textAlign: "center",
                                                fontSize: "13px",
                                                fontWeight: "600",
                                                color: "#7f8c8d",
                                                width: "250px",
                                            }}
                                        >
                                            AÇÕES
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredCategories.map((category) => (
                                        <tr
                                            key={category.id}
                                            style={{
                                                borderBottom:
                                                    "1px solid #ecf0f1",
                                                cursor: "pointer",
                                            }}
                                            onClick={() =>
                                                selectCategory(category)
                                            }
                                        >
                                            <td
                                                style={{
                                                    padding: "16px",
                                                    fontSize: "16px",
                                                    color: "#2c3e50",
                                                    fontWeight: "500",
                                                }}
                                            >
                                                {category.name}
                                            </td>
                                            <td
                                                style={{
                                                    padding: "16px",
                                                    textAlign: "center",
                                                }}
                                                onClick={(e) =>
                                                    e.stopPropagation()
                                                }
                                            >
                                                <div
                                                    style={{
                                                        display: "flex",
                                                        gap: "8px",
                                                        justifyContent:
                                                            "center",
                                                    }}
                                                >
                                                    <button
                                                        onClick={() =>
                                                            selectCategory(
                                                                category,
                                                            )
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background:
                                                                "#9b59b6",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
                                                        }}
                                                    >
                                                        Ver Linhas
                                                    </button>
                                                    <button
                                                        onClick={() =>
                                                            openEditCategoryModal(
                                                                category,
                                                            )
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background:
                                                                "#3498db",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
                                                        }}
                                                    >
                                                        Editar
                                                    </button>
                                                    <button
                                                        onClick={() =>
                                                            deleteCategory(
                                                                category.id,
                                                                category.name,
                                                            )
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background:
                                                                "#e74c3c",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
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
                        )}
                    </div>
                </>
            ) : (
                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: "24px",
                    }}
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                            border: "1px solid #ecf0f1",
                            padding: "20px",
                        }}
                    >
                        <h2
                            style={{
                                marginTop: 0,
                                marginBottom: "20px",
                                fontSize: "20px",
                                color: "#2c3e50",
                            }}
                        >
                            Informações da Categoria
                        </h2>
                        <div
                            style={{
                                padding: "16px",
                                background: "#f8f9fa",
                                borderRadius: "6px",
                            }}
                        >
                            <div style={{ marginBottom: "8px" }}>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    NOME
                                </div>
                                <div
                                    style={{
                                        fontSize: "18px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    {selectedCategory.name}
                                </div>
                            </div>
                        </div>
                        <div
                            style={{
                                marginTop: "20px",
                                display: "flex",
                                gap: "12px",
                            }}
                        >
                            <button
                                onClick={() =>
                                    openEditCategoryModal(selectedCategory)
                                }
                                style={{
                                    flex: 1,
                                    padding: "10px",
                                    background: "#3498db",
                                    color: "white",
                                    border: "none",
                                    borderRadius: "4px",
                                    cursor: "pointer",
                                    fontSize: "14px",
                                }}
                            >
                                Editar Categoria
                            </button>
                            <button
                                onClick={() =>
                                    deleteCategory(
                                        selectedCategory.id,
                                        selectedCategory.name,
                                    )
                                }
                                style={{
                                    flex: 1,
                                    padding: "10px",
                                    background: "#e74c3c",
                                    color: "white",
                                    border: "none",
                                    borderRadius: "4px",
                                    cursor: "pointer",
                                    fontSize: "14px",
                                }}
                            >
                                Deletar Categoria
                            </button>
                        </div>
                    </div>

                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                            border: "1px solid #ecf0f1",
                            padding: "20px",
                        }}
                    >
                        <h2
                            style={{
                                marginTop: 0,
                                marginBottom: "20px",
                                fontSize: "20px",
                                color: "#2c3e50",
                            }}
                        >
                            Linhas
                        </h2>

                        {lines.length === 0 ? (
                            <div
                                style={{
                                    padding: "40px 20px",
                                    textAlign: "center",
                                    color: "#7f8c8d",
                                }}
                            >
                                Nenhuma linha cadastrada nesta categoria
                            </div>
                        ) : (
                            <div
                                style={{
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: "10px",
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
                                        <div
                                            style={{
                                                fontSize: "16px",
                                                color: "#2c3e50",
                                            }}
                                        >
                                            {line.line}
                                        </div>
                                        <div
                                            style={{
                                                display: "flex",
                                                gap: "8px",
                                            }}
                                        >
                                            <button
                                                onClick={() =>
                                                    openEditLineModal(line)
                                                }
                                                style={{
                                                    padding: "6px 12px",
                                                    background: "#3498db",
                                                    color: "white",
                                                    border: "none",
                                                    borderRadius: "4px",
                                                    cursor: "pointer",
                                                    fontSize: "12px",
                                                }}
                                            >
                                                Editar
                                            </button>
                                            <button
                                                onClick={() =>
                                                    deleteLine(
                                                        line.id,
                                                        line.line,
                                                    )
                                                }
                                                style={{
                                                    padding: "6px 12px",
                                                    background: "#e74c3c",
                                                    color: "white",
                                                    border: "none",
                                                    borderRadius: "4px",
                                                    cursor: "pointer",
                                                    fontSize: "12px",
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
                </div>
            )}

            {showCategoryModal && (
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
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "30px",
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
                            {categoryMode === "create"
                                ? "Nova Categoria"
                                : "Editar Categoria"}
                        </h2>

                        <form onSubmit={handleCategorySubmit}>
                            <div style={{ marginBottom: "24px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "8px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
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
                                        border: "1px solid #ddd",
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
                                    onClick={closeCategoryModal}
                                    style={{
                                        padding: "10px 24px",
                                        background: "white",
                                        color: "#7f8c8d",
                                        border: "1px solid #ddd",
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
                                        padding: "10px 24px",
                                        background: "#27ae60",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {categoryMode === "create"
                                        ? "Criar Categoria"
                                        : "Salvar Alterações"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showLineModal && (
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
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "30px",
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
                            {lineMode === "create"
                                ? "Nova Linha"
                                : "Editar Linha"}
                        </h2>

                        <form onSubmit={handleLineSubmit}>
                            <div style={{ marginBottom: "24px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "8px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Nome da Linha *
                                </label>
                                <input
                                    type="text"
                                    value={lineForm.line}
                                    onChange={(e) =>
                                        setLineForm({
                                            ...lineForm,
                                            line: e.target.value,
                                        })
                                    }
                                    required
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
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
                                    onClick={closeLineModal}
                                    style={{
                                        padding: "10px 24px",
                                        background: "white",
                                        color: "#7f8c8d",
                                        border: "1px solid #ddd",
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
                                        padding: "10px 24px",
                                        background: "#27ae60",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {lineMode === "create"
                                        ? "Criar Linha"
                                        : "Salvar Alterações"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
