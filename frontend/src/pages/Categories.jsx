import React, { useState, useEffect } from "react";
import { categoriesApi } from "../api/categoriesApi";
import {
    filterCategories,
    getInitialCategoryForm,
    getInitialLineForm,
    formatCategoryForEdit,
    formatLineForEdit,
} from "../utils/categoryHelpers";
import CategoriesTable from "../components/categories/CategoriesTable";
import CategoryModal from "../components/categories/CategoryModal";
import LinesPanel from "../components/categories/LinesPanel";
import LineModal from "../components/categories/LineModal";

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
    const [categoryForm, setCategoryForm] = useState(getInitialCategoryForm());
    const [lineForm, setLineForm] = useState(getInitialLineForm());

    useEffect(() => {
        loadCategories();
    }, []);

    const loadCategories = async () => {
        setLoading(true);
        setError("");
        try {
            const data = await categoriesApi.loadCategories(apiUrl, token);
            setCategories(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const loadLines = async (categoryId) => {
        try {
            const data = await categoriesApi.loadLines(
                apiUrl,
                token,
                categoryId,
            );
            setLines(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateCategory = async () => {
        try {
            await categoriesApi.createCategory(apiUrl, token, categoryForm);
            await loadCategories();
            closeCategoryModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdateCategory = async () => {
        try {
            await categoriesApi.updateCategory(
                apiUrl,
                token,
                selectedCategory.id,
                categoryForm,
            );
            await loadCategories();
            closeCategoryModal();

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

    const handleDeleteCategory = async (categoryId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja deletar a categoria "${categoryName}"?\n\nIsso pode afetar contratos vinculados a esta categoria.`,
            )
        )
            return;

        try {
            await categoriesApi.deleteCategory(apiUrl, token, categoryId);
            await loadCategories();

            if (selectedCategory?.id === categoryId) {
                setSelectedCategory(null);
                setLines([]);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateLine = async () => {
        try {
            const lineData = {
                line: lineForm.line,
                category_id: selectedCategory.id,
            };
            await categoriesApi.createLine(apiUrl, token, lineData);
            await loadLines(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdateLine = async () => {
        try {
            await categoriesApi.updateLine(
                apiUrl,
                token,
                selectedLine.id,
                lineForm,
            );
            await loadLines(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDeleteLine = async (lineId, lineName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja deletar a linha "${lineName}"?\n\nIsso pode afetar contratos vinculados a esta linha.`,
            )
        )
            return;

        try {
            await categoriesApi.deleteLine(apiUrl, token, lineId);
            await loadLines(selectedCategory.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateCategoryModal = () => {
        setCategoryMode("create");
        setCategoryForm(getInitialCategoryForm());
        setShowCategoryModal(true);
    };

    const openEditCategoryModal = (category) => {
        setCategoryMode("edit");
        setSelectedCategory(category);
        setCategoryForm(formatCategoryForEdit(category));
        setShowCategoryModal(true);
    };

    const closeCategoryModal = () => {
        setShowCategoryModal(false);
        setCategoryForm(getInitialCategoryForm());
        setError("");
    };

    const openCreateLineModal = () => {
        setLineMode("create");
        setSelectedLine(null);
        setLineForm(getInitialLineForm());
        setShowLineModal(true);
    };

    const openEditLineModal = (line) => {
        setLineMode("edit");
        setSelectedLine(line);
        setLineForm(formatLineForEdit(line));
        setShowLineModal(true);
    };

    const closeLineModal = () => {
        setShowLineModal(false);
        setSelectedLine(null);
        setLineForm(getInitialLineForm());
        setError("");
    };

    const handleCategorySubmit = (e) => {
        e.preventDefault();
        if (categoryMode === "create") {
            handleCreateCategory();
        } else {
            handleUpdateCategory();
        }
    };

    const handleLineSubmit = (e) => {
        e.preventDefault();
        if (lineMode === "create") {
            handleCreateLine();
        } else {
            handleUpdateLine();
        }
    };

    const selectCategory = async (category) => {
        setSelectedCategory(category);
        await loadLines(category.id);
    };

    const filteredCategories = filterCategories(categories, searchTerm);

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
                    Categorias e Linhas
                </h1>
                <div style={{ display: "flex", gap: "12px" }}>
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

            <div style={{ marginBottom: "20px" }}>
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
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "20px",
                }}
            >
                <div
                    style={{
                        background: "white",
                        borderRadius: "8px",
                        boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                        border: "1px solid #ecf0f1",
                        overflow: "hidden",
                    }}
                >
                    <div
                        style={{
                            padding: "20px",
                            background: "#f8f9fa",
                            borderBottom: "1px solid #dee2e6",
                        }}
                    >
                        <h2
                            style={{
                                margin: 0,
                                fontSize: "20px",
                                color: "#2c3e50",
                            }}
                        >
                            Categorias
                        </h2>
                    </div>
                    <CategoriesTable
                        filteredCategories={filteredCategories}
                        onSelectCategory={selectCategory}
                        onEditCategory={openEditCategoryModal}
                        onDeleteCategory={handleDeleteCategory}
                        selectedCategory={selectedCategory}
                    />
                </div>

                <div>
                    <LinesPanel
                        selectedCategory={selectedCategory}
                        lines={lines}
                        onCreateLine={openCreateLineModal}
                        onEditLine={openEditLineModal}
                        onDeleteLine={handleDeleteLine}
                    />
                </div>
            </div>

            <CategoryModal
                showModal={showCategoryModal}
                modalMode={categoryMode}
                categoryForm={categoryForm}
                setCategoryForm={setCategoryForm}
                onSubmit={handleCategorySubmit}
                onClose={closeCategoryModal}
            />

            <LineModal
                showModal={showLineModal}
                modalMode={lineMode}
                lineForm={lineForm}
                setLineForm={setLineForm}
                onSubmit={handleLineSubmit}
                onClose={closeLineModal}
            />
        </div>
    );
}
