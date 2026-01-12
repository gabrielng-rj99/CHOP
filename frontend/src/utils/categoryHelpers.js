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

export const filterCategories = (
    categories,
    searchTerm,
    allLines,
    statusFilter = "all",
) => {
    let filtered = categories;

    // Filter by status first
    if (statusFilter === "active") {
        filtered = filtered.filter((category) => !category.archived_at);
    } else if (statusFilter === "archived") {
        filtered = filtered.filter((category) => !!category.archived_at);
    }

    // Then filter by search term
    if (!searchTerm.trim()) {
        return filtered;
    }

    const search = searchTerm.toLowerCase();
    return filtered.filter((category) => {
        // Search by category name
        if (category.name.toLowerCase().includes(search)) {
            return true;
        }

        // Search by line names if allLines is provided
        if (allLines && Array.isArray(allLines)) {
            const categoryLines = allLines.filter(
                (line) => line.category_id === category.id,
            );
            return categoryLines.some(
                (line) => line.name && line.name.toLowerCase().includes(search),
            );
        }

        return false;
    });
};

export const filterSubcategories = (
    subcategories,
    searchTerm,
    statusFilter = "all",
) => {
    let filtered = subcategories;

    // Filter by status first
    if (statusFilter === "active") {
        filtered = filtered.filter((sub) => !sub.archived_at);
    } else if (statusFilter === "archived") {
        filtered = filtered.filter((sub) => !!sub.archived_at);
    }

    // Then filter by search term
    if (!searchTerm.trim()) {
        return filtered;
    }

    const search = searchTerm.toLowerCase();
    return filtered.filter(
        (sub) => sub.name && sub.name.toLowerCase().includes(search),
    );
};

export const getInitialCategoryForm = () => ({
    name: "",
});

export const getInitialLineForm = () => ({
    line: "",
});

export const formatCategoryForEdit = (category) => ({
    name: category.name || "",
});

export const formatLineForEdit = (line) => ({
    line: line.name || "",
});
