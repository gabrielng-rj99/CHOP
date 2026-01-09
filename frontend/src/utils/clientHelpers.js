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

export const formatDate = (dateString) => {
    if (!dateString) return "-";
    // Parse date correctly to avoid timezone issues
    // If format is yyyy-mm-dd, parse manually
    if (dateString.match(/^\d{4}-\d{2}-\d{2}/)) {
        const [year, month, day] = dateString.split("T")[0].split("-");
        return `${day}/${month}/${year}`;
    }
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
    });
};

export const filterClients = (clients, filter, searchTerm) => {
    return clients.filter((client) => {
        const matchesFilter =
            (filter === "active" &&
                !client.archived_at &&
                client.status === "ativo") ||
            (filter === "inactive" &&
                !client.archived_at &&
                client.status === "inativo") ||
            (filter === "archived" && !!client.archived_at) ||
            filter === "all";

        const matchesSearch =
            searchTerm === "" ||
            client.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            client.nickname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            client.registration_id
                ?.toLowerCase()
                .includes(searchTerm.toLowerCase()) ||
            client.email?.toLowerCase().includes(searchTerm.toLowerCase());

        return matchesFilter && matchesSearch;
    });
};

export const getInitialFormData = () => ({
    name: "",
    registration_id: "",
    nickname: "",
    birth_date: "",
    email: "",
    phone: "",
    address: "",
    notes: "",
    contact_preference: "",
    tags: "",
});

export const getInitialAffiliateForm = () => ({
    name: "",
    relationship: "",
    birth_date: "",
    phone: "",
});

export const formatClientForEdit = (client) => ({
    name: client.name || "",
    registration_id: client.registration_id || "",
    nickname: client.nickname || "",
    birth_date: client.birth_date ? client.birth_date.split("T")[0] : "",
    email: client.email || "",
    phone: client.phone || "",
    address: client.address || "",
    notes: client.notes || "",
    contact_preference: client.contact_preference || "",
    tags: client.tags || "",
});

export const formatAffiliateForEdit = (affiliate) => ({
    name: affiliate.name || "",
    relationship: affiliate.relationship || "",
    birth_date: affiliate.birth_date ? affiliate.birth_date.split("T")[0] : "",
    phone: affiliate.phone || "",
});

export const prepareClientPayload = (data) => {
    const payload = { ...data };

    // Campos que devem ser enviados como null se estiverem vazios
    const nullableFields = [
        "registration_id",
        "nickname",
        "birth_date",
        "email",
        "phone",
        "address",
        "notes",
        "contact_preference",
        "tags",
        "documents"
    ];

    nullableFields.forEach((field) => {
        if (payload[field] === "" || payload[field] === undefined) {
            payload[field] = null;
        }
    });

    // Tratamento especial para datas (converter YYYY-MM-DD para RFC3339)
    if (payload.birth_date && typeof payload.birth_date === 'string' && payload.birth_date.length === 10) {
        payload.birth_date = `${payload.birth_date}T00:00:00Z`;
    }

    // Tratamento especial para telefone (remover formatação para aceitar apenas números)
    if (payload.phone) {
        payload.phone = payload.phone.replace(/\D/g, "");
        if (payload.phone === "") payload.phone = null;
    }

    return payload;
};
