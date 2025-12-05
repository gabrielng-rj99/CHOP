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

// Helper para converter data do formato yyyy-mm-dd para dd/mm/yyyy
const convertDateToDisplay = (dateString) => {
    if (!dateString) return "";
    const [year, month, day] = dateString.split("T")[0].split("-");
    return `${day}/${month}/${year}`;
};

// Helper para converter data do formato dd/mm/yyyy para yyyy-mm-ddT00:00:00Z
const convertDateToAPI = (dateString) => {
    if (!dateString) return "";
    const parts = dateString.split("/");
    if (parts.length === 3) {
        const [day, month, year] = parts;
        if (year && year.length === 4) {
            return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}T00:00:00Z`;
        }
    }
    // If already in YYYY-MM-DD format, add time
    if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
        return `${dateString}T00:00:00Z`;
    }
    return dateString;
};

export const getInitialFormData = () => ({
    model: "",
    item_key: "",
    start_date: "",
    end_date: "",
    entity_id: "",
    sub_entity_id: "",
    category_id: "",
    subcategory_id: "",
});

export const formatContractForEdit = (contract) => ({
    model: contract.model || "",
    item_key: contract.item_key || "",
    start_date: contract.start_date
        ? convertDateToDisplay(contract.start_date)
        : "",
    end_date: contract.end_date ? convertDateToDisplay(contract.end_date) : "",
    entity_id: contract.entity_id || "",
    sub_entity_id: contract.sub_entity_id || "",
    category_id: contract.line?.category_id || "",
    subcategory_id: contract.subcategory_id || "",
});

export const formatDate = (dateString) => {
    if (!dateString) return "-";
    // Parse date correctly to avoid timezone issues
    // If format is yyyy-mm-dd, parse manually
    if (dateString.match(/^\d{4}-\d{2}-\d{2}/)) {
        const [year, month, day] = dateString.split("T")[0].split("-");
        return `${day}/${month}/${year}`;
    }
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString("pt-BR", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
        });
    } catch {
        return "-";
    }
};

export const getContractStatus = (contract) => {
    // Se não tem data de término, é considerado ativo (contrato permanente)
    if (!contract.end_date || contract.end_date === "") {
        return { status: "Ativo", color: "#27ae60" };
    }

    const endDate = new Date(contract.end_date);
    const startDate = contract.start_date
        ? new Date(contract.start_date)
        : null;
    const now = new Date();

    // Se tem data de início no futuro, é "Não Iniciado"
    if (startDate && startDate > now) {
        return { status: "Não Iniciado", color: "#3498db" };
    }

    const daysUntilExpiration = Math.ceil(
        (endDate - now) / (1000 * 60 * 60 * 24),
    );

    if (daysUntilExpiration < 0) {
        return { status: "Expirado", color: "#e74c3c" };
    } else if (daysUntilExpiration <= 30) {
        return { status: "Próximo ao vencimento", color: "#f39c12" };
    } else {
        return { status: "Ativo", color: "#27ae60" };
    }
};

export const filterContracts = (
    contracts,
    filter,
    searchTerm,
    clients,
    categories,
) => {
    return contracts.filter((contract) => {
        const isArchived = !!contract.archived_at;
        const statusObj = getContractStatus(contract);
        const status = statusObj.status;

        const matchesFilter =
            (filter === "active" && !isArchived && status === "Ativo") ||
            (filter === "expiring" &&
                !isArchived &&
                status === "Próximo ao vencimento") ||
            (filter === "expired" && !isArchived && status === "Expirado") ||
            (filter === "not-started" &&
                !isArchived &&
                status === "Não Iniciado") ||
            (filter === "archived" && isArchived) ||
            (filter === "all" && !isArchived);

        const client = clients.find((c) => c.id === contract.entity_id);
        const category = categories.find((cat) =>
            cat.lines?.some((line) => line.id === contract.subcategory_id),
        );

        const matchesSearch =
            searchTerm === "" ||
            contract.model?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            contract.item_key
                ?.toLowerCase()
                .includes(searchTerm.toLowerCase()) ||
            client?.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            category?.name?.toLowerCase().includes(searchTerm.toLowerCase());

        return matchesFilter && matchesSearch;
    });
};

export const getClientName = (clientId, clients) => {
    const client = clients.find((c) => c.id === clientId);
    return client?.name || "-";
};

export const getCategoryName = (lineId, categories) => {
    const category = categories.find((cat) =>
        cat.lines?.some((line) => line.id === lineId),
    );
    return category?.name || "-";
};

// Exportar helper para conversão de data para API (usado no submit)
export const prepareContractDataForAPI = (formData) => {
    return {
        ...formData,
        start_date: formData.start_date
            ? convertDateToAPI(formData.start_date)
            : null,
        end_date: formData.end_date
            ? convertDateToAPI(formData.end_date)
            : null,
    };
};
