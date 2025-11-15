export const clientsApi = {
    loadClients: async (apiUrl, token, setClients, setError) => {
        try {
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
            setClients(data.data || []);
        } catch (err) {
            setError(err.message);
        }
    },

    createClient: async (apiUrl, token, formData) => {
        const payload = {
            name: formData.name,
            registration_id: formData.registration_id || null,
            nickname: formData.nickname || null,
            birth_date:
                formData.birth_date && formData.birth_date.trim() !== ""
                    ? formData.birth_date
                    : null,
            email: formData.email || null,
            phone: formData.phone || null,
            address: formData.address || null,
            notes: formData.notes || null,
            contact_preference: formData.contact_preference || null,
            tags: formData.tags || null,
            status: formData.status || "ativo",
        };

        const response = await fetch(`${apiUrl}/api/clients`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar cliente");
        }

        return response.json();
    },

    updateClient: async (apiUrl, token, clientId, formData) => {
        const payload = {
            name: formData.name,
            registration_id: formData.registration_id || null,
            nickname: formData.nickname || null,
            birth_date:
                formData.birth_date && formData.birth_date.trim() !== ""
                    ? formData.birth_date
                    : null,
            email: formData.email || null,
            phone: formData.phone || null,
            address: formData.address || null,
            notes: formData.notes || null,
            contact_preference: formData.contact_preference || null,
            tags: formData.tags || null,
            status: formData.status || "ativo",
        };

        const response = await fetch(`${apiUrl}/api/clients/${clientId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar cliente");
        }

        return response.json();
    },

    archiveClient: async (apiUrl, token, clientId) => {
        const response = await fetch(
            `${apiUrl}/api/clients/${clientId}/archive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (!response.ok) {
            throw new Error("Erro ao arquivar cliente");
        }

        return response.json();
    },

    unarchiveClient: async (apiUrl, token, clientId) => {
        const response = await fetch(
            `${apiUrl}/api/clients/${clientId}/unarchive`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (!response.ok) {
            throw new Error("Erro ao desarquivar cliente");
        }

        return response.json();
    },

    loadDependents: async (apiUrl, token, clientId) => {
        const response = await fetch(
            `${apiUrl}/api/clients/${clientId}/dependents`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (!response.ok) {
            throw new Error("Erro ao carregar dependentes");
        }

        const data = await response.json();
        return data.data || [];
    },

    createDependent: async (apiUrl, token, clientId, dependentForm) => {
        const payload = {
            name: dependentForm.name,
            relationship: dependentForm.relationship,
            birth_date:
                dependentForm.birth_date &&
                dependentForm.birth_date.trim() !== ""
                    ? dependentForm.birth_date
                    : null,
            phone: dependentForm.phone || null,
        };

        const response = await fetch(
            `${apiUrl}/api/clients/${clientId}/dependents`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            },
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar dependente");
        }

        return response.json();
    },

    updateDependent: async (apiUrl, token, dependentId, dependentForm) => {
        const payload = {
            name: dependentForm.name,
            relationship: dependentForm.relationship,
            birth_date:
                dependentForm.birth_date &&
                dependentForm.birth_date.trim() !== ""
                    ? dependentForm.birth_date
                    : null,
            phone: dependentForm.phone || null,
        };

        const response = await fetch(
            `${apiUrl}/api/dependents/${dependentId}`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            },
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar dependente");
        }

        return response.json();
    },

    deleteDependent: async (apiUrl, token, dependentId) => {
        const response = await fetch(
            `${apiUrl}/api/dependents/${dependentId}`,
            {
                method: "DELETE",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (!response.ok) {
            throw new Error("Erro ao deletar dependente");
        }

        return response.json();
    },
};
