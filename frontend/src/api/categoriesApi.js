const categoriesApi = {
    loadCategories: async (apiUrl, token) => {
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
        return data.data || [];
    },

    loadLines: async (apiUrl, token, categoryId) => {
        const response = await fetch(
            `${apiUrl}/api/categories/${categoryId}/lines`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!response.ok) {
            throw new Error("Erro ao carregar linhas");
        }

        const data = await response.json();
        return data.data || [];
    },

    createCategory: async (apiUrl, token, categoryData) => {
        const response = await fetch(`${apiUrl}/api/categories`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(categoryData),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar categoria");
        }

        return await response.json();
    },

    updateCategory: async (apiUrl, token, categoryId, categoryData) => {
        const response = await fetch(
            `${apiUrl}/api/categories/${categoryId}`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(categoryData),
            }
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar categoria");
        }

        return await response.json();
    },

    deleteCategory: async (apiUrl, token, categoryId) => {
        const response = await fetch(
            `${apiUrl}/api/categories/${categoryId}`,
            {
                method: "DELETE",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!response.ok) {
            throw new Error("Erro ao deletar categoria");
        }

        return await response.json();
    },

    createLine: async (apiUrl, token, lineData) => {
        const response = await fetch(`${apiUrl}/api/lines`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar linha");
        }

        return await response.json();
    },

    updateLine: async (apiUrl, token, lineId, lineData) => {
        const response = await fetch(`${apiUrl}/api/lines/${lineId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar linha");
        }

        return await response.json();
    },

    deleteLine: async (apiUrl, token, lineId) => {
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

        return await response.json();
    },
};

export { categoriesApi };
