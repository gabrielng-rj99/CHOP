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

export const agreementsApi = {
    loadAgreements: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/agreements`, {
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

    loadEntities: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/entities`, {
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

    loadSubcategories: async (apiUrl, token, categoryId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/categories/${categoryId}/subcategories`,
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

    loadSubEntities: async (apiUrl, token, clientId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/entities/${clientId}/sub_entities`,
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

    createAgreement: async (apiUrl, token, formData, onTokenExpired) => {
        const payload = {
            model: formData.model || "",
            item_key: formData.item_key || "",
            start_date: formData.start_date,
            end_date: formData.end_date,
            entity_id: formData.entity_id,
            sub_entity_id: formData.sub_entity_id || null,
            subcategory_id: formData.subcategory_id,
        };

        const response = await fetch(`${apiUrl}/agreements`, {
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

    updateAgreement: async (apiUrl, token, contractId, formData, onTokenExpired) => {
        const payload = {
            model: formData.model || "",
            item_key: formData.item_key || "",
            start_date: formData.start_date,
            end_date: formData.end_date,
            entity_id: formData.entity_id,
            sub_entity_id: formData.sub_entity_id || null,
            subcategory_id: formData.subcategory_id,
        };

        const response = await fetch(
            `${apiUrl}/agreements/${contractId}`,
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

    archiveAgreement: async (apiUrl, token, contractId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/agreements/${contractId}/archive`,
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

    unarchiveAgreement: async (apiUrl, token, contractId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/agreements/${contractId}/unarchive`,
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
