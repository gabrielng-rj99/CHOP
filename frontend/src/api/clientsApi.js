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

export const clientsApi = {
    // Direct return method for getting clients (used by AuditLogs)
    getClients: async (apiUrl, token, params = {}, onTokenExpired) => {
        const queryParams = new URLSearchParams();
        if (params.limit) queryParams.append("limit", params.limit);
        if (params.include_stats) queryParams.append("include_stats", "true");

        const url = `${apiUrl}/clients${queryParams.toString() ? "?" + queryParams.toString() : ""}`;

        const response = await fetch(url, {
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
            throw new Error("Erro ao carregar clientes");
        }

        return await response.json();
    },

    loadClients: async (
        apiUrl,
        token,
        setClients,
        setError,
        onTokenExpired,
    ) => {
        try {
            const response = await fetch(
                `${apiUrl}/clients?include_stats=true`,
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
                throw new Error("Erro ao carregar clientes");
            }

            const data = await response.json();
            setClients(data.data || []);
        } catch (err) {
            setError(err.message);
        }
    },

    createClient: async (apiUrl, token, formData, onTokenExpired) => {
        const formatDateForAPI = (dateString) => {
            if (!dateString || dateString.trim() === "") return null;
            // If already has timestamp, return as is
            if (dateString.includes("T")) return dateString;
            // If in YYYY-MM-DD format, add timestamp
            if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
                return `${dateString}T00:00:00Z`;
            }
            return dateString;
        };

        const payload = {
            name: formData.name,
            registration_id: formData.registration_id || null,
            nickname: formData.nickname || null,
            birth_date: formatDateForAPI(formData.birth_date),
            email: formData.email || null,
            phone: formData.phone || null,
            address: formData.address || null,
            notes: formData.notes || null,
            contact_preference: formData.contact_preference || null,
            tags: formData.tags || null,
        };

        const response = await fetch(`${apiUrl}/clients`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar cliente");
        }

        return response.json();
    },

    updateClient: async (apiUrl, token, clientId, formData, onTokenExpired) => {
        const formatDateForAPI = (dateString) => {
            if (!dateString || dateString.trim() === "") return null;
            // If already has timestamp, return as is
            if (dateString.includes("T")) return dateString;
            // If in YYYY-MM-DD format, add timestamp
            if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
                return `${dateString}T00:00:00Z`;
            }
            return dateString;
        };

        const payload = {
            name: formData.name,
            registration_id: formData.registration_id || null,
            nickname: formData.nickname || null,
            birth_date: formatDateForAPI(formData.birth_date),
            email: formData.email || null,
            phone: formData.phone || null,
            address: formData.address || null,
            notes: formData.notes || null,
            contact_preference: formData.contact_preference || null,
            tags: formData.tags || null,
        };

        const response = await fetch(`${apiUrl}/clients/${clientId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar cliente");
        }

        return response.json();
    },

    archiveClient: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/clients/${clientId}/archive`, {
            method: "PUT",
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
            throw new Error("Erro ao arquivar cliente");
        }

        return response.json();
    },

    unarchiveClient: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/clients/${clientId}/unarchive`,
            {
                method: "PUT",
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
            throw new Error("Erro ao desarquivar cliente");
        }

        return response.json();
    },

    loadAffiliates: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/clients/${clientId}/affiliates`,
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
            throw new Error("Erro ao carregar afiliados");
        }

        const data = await response.json();
        return data.data || [];
    },

    createAffiliate: async (
        apiUrl,
        token,
        clientId,
        affiliateForm,
        onTokenExpired,
    ) => {
        const payload = {
            name: affiliateForm.name,
            description: affiliateForm.relationship || null, // Maps frontend 'relationship' to backend 'description'
            birth_date:
                affiliateForm.birth_date &&
                affiliateForm.birth_date.trim() !== ""
                    ? affiliateForm.birth_date
                    : null,
            phone: affiliateForm.phone || null,
        };

        const response = await fetch(
            `${apiUrl}/clients/${clientId}/affiliates`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar afiliado");
        }

        return response.json();
    },

    updateAffiliate: async (
        apiUrl,
        token,
        affiliateId,
        affiliateForm,
        onTokenExpired,
    ) => {
        const payload = {
            name: affiliateForm.name,
            description: affiliateForm.relationship || null, // Maps frontend 'relationship' to backend 'description'
            birth_date:
                affiliateForm.birth_date &&
                affiliateForm.birth_date.trim() !== ""
                    ? affiliateForm.birth_date
                    : null,
            phone: affiliateForm.phone || null,
        };

        const response = await fetch(`${apiUrl}/affiliates/${affiliateId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar afiliado");
        }

        return response.json();
    },

    deleteAffiliate: async (apiUrl, token, affiliateId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/affiliates/${affiliateId}`, {
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
            throw new Error("Erro ao deletar afiliado");
        }

        return response.json();
    },
};
