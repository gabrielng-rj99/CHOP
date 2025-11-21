export const contractsApi = {
    loadContracts: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/contracts`, {
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
            throw new Error("Erro ao carregar contratos");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadClients: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/clients`, {
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
            throw new Error("Erro ao carregar clientes");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadCategories: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/categories`, {
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
            throw new Error("Erro ao carregar categorias");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadLines: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/lines`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                }
            }
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

    loadDependents: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/clients/${clientId}/dependents`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao carregar dependentes");
        }

        const data = await response.json();
        return data.data || [];
    },

    createContract: async (apiUrl, token, formData, onTokenExpired) => {
        const payload = {
            model: formData.model || "",
            product_key: formData.product_key || "",
            start_date: formData.start_date,
            end_date: formData.end_date,
            client_id: formData.client_id,
            dependent_id: formData.dependent_id || null,
            line_id: formData.line_id,
        };

        const response = await fetch(`${apiUrl}/contracts`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar contrato");
        }

        return response.json();
    },

    updateContract: async (apiUrl, token, contractId, formData, onTokenExpired) => {
        const payload = {
            model: formData.model || "",
            product_key: formData.product_key || "",
            start_date: formData.start_date,
            end_date: formData.end_date,
            client_id: formData.client_id,
            dependent_id: formData.dependent_id || null,
            line_id: formData.line_id,
        };

        const response = await fetch(
            `${apiUrl}/contracts/${contractId}`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            }
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar contrato");
        }

        return response.json();
    },

    archiveContract: async (apiUrl, token, contractId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/contracts/${contractId}/archive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao arquivar contrato");
        }

        return response.json();
    },

    unarchiveContract: async (apiUrl, token, contractId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/contracts/${contractId}/unarchive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao desarquivar contrato");
        }

        return response.json();
    },
};
