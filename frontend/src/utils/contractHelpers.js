export const getInitialFormData = () => ({
    model: "",
    product_key: "",
    start_date: "",
    end_date: "",
    client_id: "",
    dependent_id: "",
    category_id: "",
    line_id: "",
});

export const formatContractForEdit = (contract) => ({
    model: contract.model || "",
    product_key: contract.product_key || "",
    start_date: contract.start_date ? contract.start_date.split("T")[0] : "",
    end_date: contract.end_date || "",
    client_id: contract.client_id || "",
    dependent_id: contract.dependent_id || "",
    category_id: contract.line?.category_id || "",
    line_id: contract.line_id || "",
});

export const formatDate = (dateString) => {
    if (!dateString) return "-";
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR");
};

export const getContractStatus = (endDate) => {
    const now = new Date();
    const daysUntilExpiration = Math.ceil(
        (new Date(endDate) - now) / (1000 * 60 * 60 * 24)
    );

    if (daysUntilExpiration < 0) {
        return { status: "Expirado", color: "#e74c3c" };
    } else if (daysUntilExpiration <= 30) {
        return { status: "Próximo ao vencimento", color: "#f39c12" };
    } else {
        return { status: "Ativo", color: "#27ae60" };
    }
};

export const filterContracts = (contracts, filter, searchTerm, clients, categories) => {
    return contracts
        .filter((contract) => {
            const isArchived = !!contract.archived_at;
            const status = getContractStatus(contract.end_date).status;

            const matchesFilter =
                (filter === "active" && !isArchived && status === "Ativo") ||
                (filter === "expiring" && !isArchived && status === "Próximo ao vencimento") ||
                (filter === "expired" && !isArchived && status === "Expirado") ||
                (filter === "archived" && isArchived) ||
                (filter === "all" && !isArchived);

            const client = clients.find((c) => c.id === contract.client_id);
            const category = categories.find((cat) =>
                cat.lines?.some((line) => line.id === contract.line_id)
            );

            const matchesSearch =
                searchTerm === "" ||
                contract.model?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                contract.product_key?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                client?.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                category?.name?.toLowerCase().includes(searchTerm.toLowerCase());

            return matchesFilter && matchesSearch;
        })
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
};

export const getClientName = (clientId, clients) => {
    const client = clients.find((c) => c.id === clientId);
    return client?.name || "-";
};

export const getCategoryName = (lineId, categories) => {
    const category = categories.find((cat) =>
        cat.lines?.some((line) => line.id === lineId)
    );
    return category?.name || "-";
};
