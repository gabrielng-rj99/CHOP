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

const categoriesApi = {
    loadCategories: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories?include_archived=true`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao carregar categorias");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadSubcategories: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/subcategories?include_archived=true`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao carregar linhas");
        }

        const data = await response.json();
        return data.data || [];
    },

    createCategory: async (apiUrl, token, categoryData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/categories`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(categoryData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar categoria");
        }

        return await response.json();
    },

    updateCategory: async (
        apiUrl,
        token,
        categoryId,
        categoryData,
        onTokenExpired,
    ) => {
        const response = await fetch(`${apiUrl}/categories/${categoryId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(categoryData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar categoria");
        }

        return await response.json();
    },

    deleteCategory: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/categories/${categoryId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao deletar categoria");
        }

        return await response.json();
    },

    archiveCategory: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/archive`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao arquivar categoria");
        }

        return await response.json();
    },

    unarchiveCategory: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/unarchive`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao desarquivar categoria");
        }

        return await response.json();
    },

    createSubcategory: async (apiUrl, token, lineData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/subcategories`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar linha");
        }

        return await response.json();
    },

    updateSubcategory: async (
        apiUrl,
        token,
        lineId,
        lineData,
        onTokenExpired,
    ) => {
        const response = await fetch(`${apiUrl}/subcategories/${lineId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar linha");
        }

        return await response.json();
    },

    deleteSubcategory: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/subcategories/${lineId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao deletar linha");
        }

        return await response.json();
    },

    archiveSubcategory: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/subcategories/${lineId}/archive`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao arquivar linha");
        }

        return await response.json();
    },

    unarchiveSubcategory: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/subcategories/${lineId}/unarchive`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao desarquivar linha");
        }

        return await response.json();
    },
};

export { categoriesApi };
