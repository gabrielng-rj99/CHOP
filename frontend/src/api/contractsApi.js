export const contractsApi = {
    loadContracts: async (apiUrl, token) => {
        const response = await fetch(`${apiUrl}/api/contracts`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (!response.ok) {
            throw new Error("Erro ao carregar contratos");
        }

        const data = await response.json();
        return data.data || [];
    },

    loadClients: async (apiUrl, token) => {
        const response = await fetch(`${apiUrl}/api/clients`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (!response.ok) {
            throw new Error("Erro ao carregar clientes");
        }

        const data = await response.json();
        return data.data || [];
    },

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

    loadDependents: async (apiUrl, token, clientId) => {
        const response = await fetch(
            `${apiUrl}/api/clients/${clientId}/dependents`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!response.ok) {
            throw new Error("Erro ao carregar dependentes");
        }

        const data = await response.json();
        return data.data || [];
    },

    createContract: async (apiUrl, token, formData) => {
        const payload = {
            model: formData.model || "",
            product_key: formData.product_key || "",
            start_date: formData.start_date,
            end_date: formData.end_date,
            client_id: formData.client_id,
            dependent_id: formData.dependent_id || null,
            line_id: formData.line_id,
        };

        const response = await fetch(`${apiUrl}/api/contracts`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar contrato");
        }

        return response.json();
    },

    updateContract: async (apiUrl, token, contractId, formData) => {
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
            `${apiUrl}/api/contracts/${contractId}`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            }
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar contrato");
        }

        return response.json();
    },

    archiveContract: async (apiUrl, token, contractId) => {
        const response = await fetch(
            `${apiUrl}/api/contracts/${contractId}/archive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!response.ok) {
            throw new Error("Erro ao arquivar contrato");
        }

        return response.json();
    },

    unarchiveContract: async (apiUrl, token, contractId) => {
        const response = await fetch(
            `${apiUrl}/api/contracts/${contractId}/unarchive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!response.ok) {
            throw new Error("Erro ao desarquivar contrato");
        }

        return response.json();
    },
};
