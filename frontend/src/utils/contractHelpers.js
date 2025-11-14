// Helper para converter data do formato yyyy-mm-dd para dd/mm/yyyy
const convertDateToDisplay = (dateString) => {
    if (!dateString) return "";
    const [year, month, day] = dateString.split("T")[0].split("-");
    return `${day}/${month}/${year}`;
};

// Helper para converter data do formato dd/mm/yyyy para yyyy-mm-dd
const convertDateToAPI = (dateString) => {
    if (!dateString) return "";
    const parts = dateString.split("/");
    if (parts.length === 3) {
        const [day, month, year] = parts;
        if (year && year.length === 4) {
            return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
        }
    }
    return dateString;
};

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
    start_date: contract.start_date
        ? convertDateToDisplay(contract.start_date)
        : "",
    end_date: contract.end_date ? convertDateToDisplay(contract.end_date) : "",
    client_id: contract.client_id || "",
    dependent_id: contract.dependent_id || "",
    category_id: contract.line?.category_id || "",
    line_id: contract.line_id || "",
});

export const formatDate = (dateString) => {
    if (!dateString) return "-";
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString("pt-BR");
    } catch {
        return "-";
    }
};

export const getContractStatus = (contract) => {
    // Se não tem data de término, é considerado ativo (contrato permanente)
    if (!contract.end_date) {
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

        const client = clients.find((c) => c.id === contract.client_id);
        const category = categories.find((cat) =>
            cat.lines?.some((line) => line.id === contract.line_id),
        );

        const matchesSearch =
            searchTerm === "" ||
            contract.model?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            contract.product_key
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
