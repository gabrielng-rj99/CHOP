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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao carregar categorias");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadLines: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/lines?include_archived=true`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar categoria");
        }

        return await response.json();
    },

    updateCategory: async (apiUrl, token, categoryId, categoryData, onTokenExpired) => {
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao desarquivar categoria");
        }

        return await response.json();
    },

    createLine: async (apiUrl, token, lineData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/lines`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar linha");
        }

        return await response.json();
    },

    updateLine: async (apiUrl, token, lineId, lineData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/lines/${lineId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(lineData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar linha");
        }

        return await response.json();
    },

    deleteLine: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/lines/${lineId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao deletar linha");
        }

        return await response.json();
    },

    archiveLine: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/lines/${lineId}/archive`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao arquivar linha");
        }

        return await response.json();
    },

    unarchiveLine: async (apiUrl, token, lineId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/lines/${lineId}/unarchive`,
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
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao desarquivar linha");
        }

        return await response.json();
    },
};

export { categoriesApi };
