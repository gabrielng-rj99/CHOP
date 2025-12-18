/*
 * This file is part of Entity Hub Open Project.
 * Copyright (C) 2025 Entity Hub Contributors
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

export const entitiesApi = {
    loadEntities: async (apiUrl, token, setEntities, setError, onTokenExpired) => {
        try {
            const response = await fetch(
                `${apiUrl}/entities?include_stats=true`,
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
                throw new Error("Erro ao carregar clientes");
            }

            const data = await response.json();
            setEntities(data.data || []);
        } catch (err) {
            setError(err.message);
        }
    },

    createEntity: async (apiUrl, token, formData, onTokenExpired) => {
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

        const response = await fetch(`${apiUrl}/entities`, {
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

    updateEntity: async (apiUrl, token, clientId, formData, onTokenExpired) => {
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

        const response = await fetch(`${apiUrl}/entities/${clientId}`, {
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

    archiveEntity: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/entities/${clientId}/archive`, {
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

    unarchiveEntity: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/entities/${clientId}/unarchive`,
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

    loadSubEntities: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/entities/${clientId}/sub_entities`,
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
            throw new Error("Erro ao carregar dependentes");
        }

        const data = await response.json();
        return data.data || [];
    },

    createSubEntity: async (
        apiUrl,
        token,
        clientId,
        dependentForm,
        onTokenExpired,
    ) => {
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
            `${apiUrl}/entities/${clientId}/sub_entities`,
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
            throw new Error(errorData.error || "Erro ao criar dependente");
        }

        return response.json();
    },

    updateSubEntity: async (
        apiUrl,
        token,
        dependentId,
        dependentForm,
        onTokenExpired,
    ) => {
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

        const response = await fetch(`${apiUrl}/sub_entities/${dependentId}`, {
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
            throw new Error(errorData.error || "Erro ao atualizar dependente");
        }

        return response.json();
    },

    deleteSubEntity: async (apiUrl, token, dependentId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/sub_entities/${dependentId}`, {
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
            throw new Error("Erro ao deletar dependente");
        }

        return response.json();
    },
};
