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
import "./Categories.css";

export default function Categories({ token, apiUrl }) {
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [allLines, setAllLines] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [lineModalError, setLineModalError] = useState("");
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

            // Load all lines for all categories for search functionality
            const allLinesPromises = data.map((category) =>
                categoriesApi
                    .loadLines(apiUrl, token, category.id)
                    .catch(() => []),
            );
            const allLinesResults = await Promise.all(allLinesPromises);
            const flattenedLines = allLinesResults.flat();
            setAllLines(flattenedLines);
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
            if (
                err.message &&
                err.message.includes("duplicate key value") &&
                err.message.includes("categories_name_key")
            ) {
                setError("Já existe uma categoria com esse nome.");
            } else {
                setError(err.message);
            }
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
            if (
                err.message &&
                err.message.includes("duplicate key value") &&
                err.message.includes("categories_name_key")
            ) {
                setError("Já existe uma categoria com esse nome.");
            } else {
                setError(err.message);
            }
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

    const handleArchiveCategory = async (categoryId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja arquivar a categoria "${categoryName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.archiveCategory(apiUrl, token, categoryId);
            await loadCategories();

            if (selectedCategory?.id === categoryId) {
                setSelectedCategory(null);
                setLines([]);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveCategory = async (categoryId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja desarquivar a categoria "${categoryName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.unarchiveCategory(apiUrl, token, categoryId);
            await loadCategories();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateLine = async () => {
        setLineModalError("");
        try {
            const lineData = {
                line: lineForm.line,
                category_id: selectedCategory.id,
            };
            await categoriesApi.createLine(apiUrl, token, lineData);
            await loadLines(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setLineModalError(err.message);
        }
    };

    const handleUpdateLine = async () => {
        setLineModalError("");
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
            setLineModalError(err.message);
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

    const handleArchiveLine = async (lineId, lineName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja arquivar a linha "${lineName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.archiveLine(apiUrl, token, lineId);
            await loadLines(selectedCategory.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveLine = async (lineId, lineName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja desarquivar a linha "${lineName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.unarchiveLine(apiUrl, token, lineId);
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
        setSelectedCategory(null);
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
        setLineModalError("");
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

    function compareAlphaNum(a, b) {
        const regex = /(.*?)(\d+)$/;
        const aMatch = (a.name || "").match(regex);
        const bMatch = (b.name || "").match(regex);

        if (aMatch && bMatch && aMatch[1] === bMatch[1]) {
            // Se prefixo igual, compara número como inteiro
            return parseInt(aMatch[2], 10) - parseInt(bMatch[2], 10);
        }
        // Caso contrário, ordena normalmente
        return (a.name || "").localeCompare(b.name || "");
    }

    const filteredCategories = filterCategories(
        [...categories].sort(compareAlphaNum),
        searchTerm,
        allLines,
    );

    if (loading) {
        return (
            <div className="categories-loading">
                <div className="categories-loading-text">
                    Carregando categorias...
                </div>
            </div>
        );
    }

    return (
        <div className="categories-container">
            <div className="categories-header">
                <h1 className="categories-title">
                    Categorias e Linhas dos Produtos
                </h1>
                <div className="categories-button-group">
                    <button
                        onClick={loadCategories}
                        className="categories-button-secondary"
                    >
                        Atualizar
                    </button>
                    <button
                        onClick={openCreateCategoryModal}
                        className="categories-button"
                    >
                        + Nova Categoria
                    </button>
                </div>
            </div>

            {error && !showCategoryModal && (
                <div className="categories-error">{error}</div>
            )}

            <div className="categories-search-container">
                <input
                    type="text"
                    placeholder="Buscar categorias (ou linhas do produto)..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="categories-search-input"
                />
            </div>

            <div className="categories-table-wrapper">
                {/* <div className="categories-table-header">
                    <h2 className="categories-table-header-title">
                        Categorias
                    </h2>
                    <div className="categories-table-hint">
                        Clique no ícone{" "}
                        <i
                            className="fa-light fa-box-open"
                            style={{
                                fontSize: "14px",
                                color: "#9b59b6",
                                verticalAlign: "middle",
                            }}
                        ></i>{" "}
                        para visualizar as linhas
                    </div>
                </div>*/}
                <CategoriesTable
                    filteredCategories={filteredCategories}
                    onSelectCategory={selectCategory}
                    onEditCategory={openEditCategoryModal}
                    onDeleteCategory={handleDeleteCategory}
                    onArchiveCategory={handleArchiveCategory}
                    onUnarchiveCategory={handleUnarchiveCategory}
                    selectedCategory={selectedCategory}
                />
            </div>

            {selectedCategory && !showCategoryModal && (
                <LinesPanel
                    selectedCategory={selectedCategory}
                    lines={lines}
                    onCreateLine={openCreateLineModal}
                    onEditLine={openEditLineModal}
                    onDeleteLine={handleDeleteLine}
                    onArchiveLine={handleArchiveLine}
                    onUnarchiveLine={handleUnarchiveLine}
                    onClose={() => setSelectedCategory(null)}
                />
            )}

            <CategoryModal
                showModal={showCategoryModal}
                modalMode={categoryMode}
                categoryForm={categoryForm}
                setCategoryForm={setCategoryForm}
                onSubmit={handleCategorySubmit}
                onClose={closeCategoryModal}
                error={error}
            />

            <LineModal
                showModal={showLineModal}
                modalMode={lineMode}
                lineForm={lineForm}
                setLineForm={setLineForm}
                onSubmit={handleLineSubmit}
                onClose={closeLineModal}
                error={lineModalError}
            />
        </div>
    );
}
