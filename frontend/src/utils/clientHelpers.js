export const formatDate = (dateString) => {
    if (!dateString) return "-";
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR");
};

export const filterClients = (clients, filter, searchTerm) => {
    return clients.filter((client) => {
        const matchesFilter =
            (filter === "active" &&
                !client.archived_at &&
                client.status === "ativo") ||
            (filter === "archived" && !!client.archived_at) ||
            (filter === "all" && !client.archived_at);

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

export const getInitialDependentForm = () => ({
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

export const formatDependentForEdit = (dependent) => ({
    name: dependent.name || "",
    relationship: dependent.relationship || "",
    birth_date: dependent.birth_date ? dependent.birth_date.split("T")[0] : "",
    phone: dependent.phone || "",
});
