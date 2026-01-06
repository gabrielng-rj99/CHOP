/*
 * This file is part of Client Hub Open Project.
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React, { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { categoriesApi } from "../api/categoriesApi";
import { useConfig } from "../contexts/ConfigContext";
import { useUrlState } from "../hooks/useUrlState";
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
import PrimaryButton from "../components/common/PrimaryButton";
import "./styles/Categories.css";

export default function Categories({ token, apiUrl, onTokenExpired }) {
    const { config, getGenderHelpers } = useConfig();
    const { labels } = config;
    const gCat = getGenderHelpers("category");
    // const gSub = getGenderHelpers(labels.subcategory_gender || 'F');

    const CATEGORY_LABEL = labels.categories || "Categorias";
    const SUBCATEGORY_LABEL = labels.subcategories || "Subcategorias";
    const NEW_CATEGORY_LABEL = `+ ${gCat.new} ${labels.category || "Categoria"}`;

    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [allLines, setAllLines] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [lineModalError, setLineModalError] = useState("");

    // State persistence
    const { values, updateValue } = useUrlState(
        { search: "", categoryId: "" },
        { debounce: true, debounceTime: 300 },
    );
    const searchTerm = values.search;
    const categoryId = values.categoryId;
    const setSearchTerm = (val) => updateValue("search", val);

    const [selectedCategory, setSelectedCategory] = useState(null);
    const [showCategoryModal, setShowCategoryModal] = useState(false);
    const [showLineModal, setShowLineModal] = useState(false);
    const [categoryMode, setCategoryMode] = useState("create");
    const [lineMode, setLineMode] = useState("create");
    const [selectedLine, setSelectedLine] = useState(null);
    const [categoryForm, setCategoryForm] = useState(getInitialCategoryForm());
    const [lineForm, setLineForm] = useState(getInitialLineForm());

    useEffect(() => {
        loadCategories();
    }, []);

    // Sync selectedCategory from URL
    useEffect(() => {
        if (categories.length > 0) {
            if (categoryId) {
                const cat = categories.find((c) => c.id == categoryId);
                if (cat) {
                    // Only update if different to avoid loops or unnecessary re-renders
                    if (!selectedCategory || selectedCategory.id !== cat.id) {
                        setSelectedCategory(cat);
                        loadSubcategories(cat.id);
                    }
                }
            } else {
                if (selectedCategory) {
                    setSelectedCategory(null);
                    setLines([]);
                }
            }
        }
    }, [categoryId, categories]);

    const loadCategories = async () => {
        setLoading(true);
        setError("");
        try {
            const data = await categoriesApi.loadCategories(
                apiUrl,
                token,
                onTokenExpired,
            );
            setCategories(data);

            // Load all lines for all categories for search functionality
            const allLinesPromises = data.map((category) =>
                categoriesApi
                    .loadSubcategories(
                        apiUrl,
                        token,
                        category.id,
                        onTokenExpired,
                    )
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

    const loadSubcategories = async (categoryId) => {
        try {
            const data = await categoriesApi.loadSubcategories(
                apiUrl,
                token,
                categoryId,
                onTokenExpired,
            );
            setLines(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateCategory = async () => {
        try {
            await categoriesApi.createCategory(
                apiUrl,
                token,
                categoryForm,
                onTokenExpired,
            );
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
                onTokenExpired,
            );
            await loadCategories();
            closeCategoryModal();

            // selectedCategory will be updated via effect if categories changed
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

    const handleDeleteCategory = async (catId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja deletar a categoria "${categoryName}"?\n\nIsso pode afetar contratos vinculados a esta categoria.`,
            )
        )
            return;

        try {
            await categoriesApi.deleteCategory(
                apiUrl,
                token,
                catId,
                onTokenExpired,
            );
            await loadCategories();

            if (selectedCategory?.id === catId) {
                updateValue("categoryId", ""); // Close panel via URL
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const handleArchiveCategory = async (catId, categoryName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja arquivar a categoria "${categoryName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.archiveCategory(
                apiUrl,
                token,
                catId,
                onTokenExpired,
            );
            await loadCategories();

            if (selectedCategory?.id === catId) {
                updateValue("categoryId", "");
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
            await categoriesApi.unarchiveCategory(
                apiUrl,
                token,
                categoryId,
                onTokenExpired,
            );
            await loadCategories();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateLine = async () => {
        setLineModalError("");

        // Validate whitespace-only names
        const lineName = lineForm.line?.trim();
        if (!lineName) {
            setLineModalError(
                "O nome da linha não pode ser vazio ou conter apenas espaços.",
            );
            return;
        }

        try {
            const lineData = {
                name: lineName,
                category_id: selectedCategory.id,
            };
            await categoriesApi.createSubcategory(
                apiUrl,
                token,
                lineData,
                onTokenExpired,
            );
            await loadSubcategories(selectedCategory.id);
            closeLineModal();
        } catch (err) {
            setLineModalError(err.message);
        }
    };

    const handleUpdateLine = async () => {
        setLineModalError("");

        // Validate whitespace-only names
        const lineName = lineForm.line?.trim();
        if (!lineName) {
            setLineModalError(
                "O nome da linha não pode ser vazio ou conter apenas espaços.",
            );
            return;
        }

        try {
            const lineData = {
                name: lineName,
            };
            await categoriesApi.updateSubcategory(
                apiUrl,
                token,
                selectedLine.id,
                lineData,
                onTokenExpired,
            );
            await loadSubcategories(selectedCategory.id);
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
            await categoriesApi.deleteSubcategory(
                apiUrl,
                token,
                lineId,
                onTokenExpired,
            );
            await loadSubcategories(selectedCategory.id);
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
            await categoriesApi.archiveSubcategory(
                apiUrl,
                token,
                lineId,
                onTokenExpired,
            );
            await loadSubcategories(selectedCategory.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveSubcategory = async (lineId, lineName) => {
        if (
            !window.confirm(
                `Tem certeza que deseja desarquivar a linha "${lineName}"?`,
            )
        )
            return;

        try {
            await categoriesApi.unarchiveSubcategory(
                apiUrl,
                token,
                lineId,
                onTokenExpired,
            );
            await loadSubcategories(selectedCategory.id);
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
        setSelectedCategory(category); // This is for the modal's internal use
        setCategoryForm(formatCategoryForEdit(category));
        setShowCategoryModal(true);
        updateValue("categoryId", category.id); // Also update URL to reflect selection
    };

    const closeCategoryModal = () => {
        setShowCategoryModal(false);
        setCategoryForm(getInitialCategoryForm());
        setError("");
        // Clear the categoryId from the URL when the modal is closed,
        // which will then trigger the useEffect to clear selectedCategory.
        updateValue("categoryId", "");
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
        // Update URL to persist selection
        updateValue("categoryId", category ? category.id : "");
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
                    🏷️ {config.labels.categories || "Categorias"} e{" "}
                    {config.labels.subcategories || "Subcategorias"}
                </h1>
                <div className="button-group">
                    <PrimaryButton onClick={openCreateCategoryModal}>
                        {NEW_CATEGORY_LABEL}
                    </PrimaryButton>
                </div>
            </div>

            {error && !showCategoryModal && (
                <div className="categories-error">{error}</div>
            )}

            <div className="categories-search-container">
                <input
                    type="text"
                    placeholder={`Buscar ${CATEGORY_LABEL.toLowerCase()} (ou ${SUBCATEGORY_LABEL.toLowerCase()})...`}
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="categories-search-input"
                />
            </div>

            <div className="categories-table-wrapper">
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
                    onUnarchiveSubcategory={handleUnarchiveSubcategory}
                    onClose={() => updateValue("categoryId", "")}
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
