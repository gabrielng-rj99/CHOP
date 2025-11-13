import React, { useState, useEffect } from "react";

export default function Clients({ token, apiUrl }) {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [filter, setFilter] = useState("all");
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedClient, setSelectedClient] = useState(null);
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [showDependents, setShowDependents] = useState(false);
    const [dependents, setDependents] = useState([]);
    const [selectedDependent, setSelectedDependent] = useState(null);
    const [formData, setFormData] = useState({
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
    const [dependentForm, setDependentForm] = useState({
        name: "",
        relationship: "",
        birth_date: "",
        phone: "",
    });

    useEffect(() => {
        loadClients();
    }, []);

    const loadClients = async () => {
        setLoading(true);
        setError("");

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
        } finally {
            setLoading(false);
        }
    };

    const loadDependents = async (clientId) => {
        try {
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
            setDependents(data.data || []);
        } catch (err) {
            setError(err.message);
        }
    };

    const createClient = async () => {
        try {
            const payload = {
                name: formData.name,
                registration_id: formData.registration_id || null,
                nickname: formData.nickname || null,
                birth_date: formData.birth_date || null,
                email: formData.email || null,
                phone: formData.phone || null,
                address: formData.address || null,
                notes: formData.notes || null,
                contact_preference: formData.contact_preference || null,
                tags: formData.tags || null,
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

            await loadClients();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateClient = async () => {
        try {
            const payload = {
                name: formData.name,
                registration_id: formData.registration_id || null,
                nickname: formData.nickname || null,
                birth_date: formData.birth_date || null,
                email: formData.email || null,
                phone: formData.phone || null,
                address: formData.address || null,
                notes: formData.notes || null,
                contact_preference: formData.contact_preference || null,
                tags: formData.tags || null,
            };

            const response = await fetch(
                `${apiUrl}/api/clients/${selectedClient.id}`,
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
                throw new Error(errorData.error || "Erro ao atualizar cliente");
            }

            await loadClients();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const archiveClient = async (clientId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este cliente?"))
            return;

        try {
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

            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveClient = async (clientId) => {
        try {
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

            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const createDependent = async () => {
        try {
            const payload = {
                name: dependentForm.name,
                relationship: dependentForm.relationship,
                birth_date: dependentForm.birth_date || null,
                phone: dependentForm.phone || null,
            };

            const response = await fetch(
                `${apiUrl}/api/clients/${selectedClient.id}/dependents`,
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

            await loadDependents(selectedClient.id);
            setDependentForm({
                name: "",
                relationship: "",
                birth_date: "",
                phone: "",
            });
            setSelectedDependent(null);
        } catch (err) {
            setError(err.message);
        }
    };

    const updateDependent = async () => {
        try {
            const payload = {
                name: dependentForm.name,
                relationship: dependentForm.relationship,
                birth_date: dependentForm.birth_date || null,
                phone: dependentForm.phone || null,
            };

            const response = await fetch(
                `${apiUrl}/api/dependents/${selectedDependent.id}`,
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
                throw new Error(
                    errorData.error || "Erro ao atualizar dependente",
                );
            }

            await loadDependents(selectedClient.id);
            setDependentForm({
                name: "",
                relationship: "",
                birth_date: "",
                phone: "",
            });
            setSelectedDependent(null);
        } catch (err) {
            setError(err.message);
        }
    };

    const deleteDependent = async (dependentId) => {
        if (!window.confirm("Tem certeza que deseja deletar este dependente?"))
            return;

        try {
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

            await loadDependents(selectedClient.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData({
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
        setShowModal(true);
    };

    const openEditModal = (client) => {
        setModalMode("edit");
        setSelectedClient(client);
        setFormData({
            name: client.name || "",
            registration_id: client.registration_id || "",
            nickname: client.nickname || "",
            birth_date: client.birth_date
                ? client.birth_date.split("T")[0]
                : "",
            email: client.email || "",
            phone: client.phone || "",
            address: client.address || "",
            notes: client.notes || "",
            contact_preference: client.contact_preference || "",
            tags: client.tags || "",
        });
        setShowModal(true);
    };

    const openDependentsModal = async (client) => {
        setSelectedClient(client);
        await loadDependents(client.id);
        setShowDependents(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedClient(null);
        setError("");
    };

    const closeDependentsModal = () => {
        setShowDependents(false);
        setSelectedClient(null);
        setDependents([]);
        setSelectedDependent(null);
        setDependentForm({
            name: "",
            relationship: "",
            birth_date: "",
            phone: "",
        });
        setError("");
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            createClient();
        } else {
            updateClient();
        }
    };

    const handleDependentSubmit = (e) => {
        e.preventDefault();
        if (selectedDependent) {
            updateDependent();
        } else {
            createDependent();
        }
    };

    const editDependent = (dependent) => {
        setSelectedDependent(dependent);
        setDependentForm({
            name: dependent.name || "",
            relationship: dependent.relationship || "",
            birth_date: dependent.birth_date
                ? dependent.birth_date.split("T")[0]
                : "",
            phone: dependent.phone || "",
        });
    };

    const cancelDependentEdit = () => {
        setSelectedDependent(null);
        setDependentForm({
            name: "",
            relationship: "",
            birth_date: "",
            phone: "",
        });
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        const date = new Date(dateString);
        return date.toLocaleDateString("pt-BR");
    };

    const filteredClients = clients.filter((client) => {
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

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "60px" }}>
                <div style={{ fontSize: "18px", color: "#7f8c8d" }}>
                    Carregando clientes...
                </div>
            </div>
        );
    }

    return (
        <div>
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "30px",
                }}
            >
                <h1 style={{ fontSize: "32px", color: "#2c3e50", margin: 0 }}>
                    Clientes
                </h1>
                <div style={{ display: "flex", gap: "12px" }}>
                    <button
                        onClick={loadClients}
                        style={{
                            padding: "10px 20px",
                            background: "white",
                            color: "#3498db",
                            border: "1px solid #3498db",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                        }}
                    >
                        Atualizar
                    </button>
                    <button
                        onClick={openCreateModal}
                        style={{
                            padding: "10px 20px",
                            background: "#27ae60",
                            color: "white",
                            border: "none",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                            fontWeight: "600",
                        }}
                    >
                        + Novo Cliente
                    </button>
                </div>
            </div>

            {error && (
                <div
                    style={{
                        background: "#fee",
                        color: "#c33",
                        padding: "16px",
                        borderRadius: "4px",
                        border: "1px solid #fcc",
                        marginBottom: "20px",
                    }}
                >
                    {error}
                </div>
            )}

            <div
                style={{
                    display: "flex",
                    gap: "12px",
                    marginBottom: "24px",
                    flexWrap: "wrap",
                    alignItems: "center",
                }}
            >
                <button
                    onClick={() => setFilter("all")}
                    style={{
                        padding: "8px 16px",
                        background: filter === "all" ? "#3498db" : "white",
                        color: filter === "all" ? "white" : "#2c3e50",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                    }}
                >
                    Todos ({clients.filter((c) => !c.archived_at).length})
                </button>
                <button
                    onClick={() => setFilter("active")}
                    style={{
                        padding: "8px 16px",
                        background: filter === "active" ? "#27ae60" : "white",
                        color: filter === "active" ? "white" : "#2c3e50",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                    }}
                >
                    Ativos
                </button>
                <button
                    onClick={() => setFilter("archived")}
                    style={{
                        padding: "8px 16px",
                        background: filter === "archived" ? "#95a5a6" : "white",
                        color: filter === "archived" ? "white" : "#2c3e50",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                    }}
                >
                    Arquivados
                </button>

                <input
                    type="text"
                    placeholder="Buscar por nome, apelido, CPF/CNPJ, email..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    style={{
                        flex: 1,
                        minWidth: "300px",
                        padding: "8px 16px",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                />
            </div>

            <div
                style={{
                    background: "white",
                    borderRadius: "8px",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                    border: "1px solid #ecf0f1",
                    overflow: "hidden",
                }}
            >
                {filteredClients.length === 0 ? (
                    <div
                        style={{
                            padding: "40px",
                            textAlign: "center",
                            color: "#7f8c8d",
                        }}
                    >
                        Nenhum cliente encontrado
                    </div>
                ) : (
                    <table
                        style={{ width: "100%", borderCollapse: "collapse" }}
                    >
                        <thead>
                            <tr
                                style={{
                                    background: "#f8f9fa",
                                    borderBottom: "2px solid #ecf0f1",
                                }}
                            >
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    NOME
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    CPF/CNPJ
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    EMAIL
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    TELEFONE
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "left",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    STATUS
                                </th>
                                <th
                                    style={{
                                        padding: "16px",
                                        textAlign: "center",
                                        fontSize: "13px",
                                        fontWeight: "600",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    AÇÕES
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredClients.map((client) => {
                                const statusColor =
                                    client.status === "ativo"
                                        ? "#27ae60"
                                        : "#95a5a6";
                                const isArchived = !!client.archived_at;
                                return (
                                    <tr
                                        key={client.id}
                                        style={{
                                            borderBottom: "1px solid #ecf0f1",
                                        }}
                                    >
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#2c3e50",
                                                fontWeight: "500",
                                            }}
                                        >
                                            {client.name}
                                            {client.nickname && (
                                                <div
                                                    style={{
                                                        fontSize: "12px",
                                                        color: "#7f8c8d",
                                                        fontWeight: "normal",
                                                    }}
                                                >
                                                    {client.nickname}
                                                </div>
                                            )}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                                fontFamily: "monospace",
                                            }}
                                        >
                                            {client.registration_id || "-"}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {client.email || "-"}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {client.phone || "-"}
                                        </td>
                                        <td style={{ padding: "16px" }}>
                                            <span
                                                style={{
                                                    display: "inline-block",
                                                    padding: "4px 12px",
                                                    borderRadius: "12px",
                                                    fontSize: "12px",
                                                    fontWeight: "600",
                                                    background:
                                                        statusColor + "20",
                                                    color: statusColor,
                                                    textTransform: "capitalize",
                                                }}
                                            >
                                                {isArchived
                                                    ? "Arquivado"
                                                    : client.status}
                                            </span>
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                textAlign: "center",
                                            }}
                                        >
                                            <div
                                                style={{
                                                    display: "flex",
                                                    gap: "8px",
                                                    justifyContent: "center",
                                                }}
                                            >
                                                <button
                                                    onClick={() =>
                                                        openEditModal(client)
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#3498db",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "12px",
                                                    }}
                                                >
                                                    Editar
                                                </button>
                                                <button
                                                    onClick={() =>
                                                        openDependentsModal(
                                                            client,
                                                        )
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#9b59b6",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "12px",
                                                    }}
                                                >
                                                    Dependentes
                                                </button>
                                                {isArchived ? (
                                                    <button
                                                        onClick={() =>
                                                            unarchiveClient(
                                                                client.id,
                                                            )
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background:
                                                                "#27ae60",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
                                                        }}
                                                    >
                                                        Desarquivar
                                                    </button>
                                                ) : (
                                                    <button
                                                        onClick={() =>
                                                            archiveClient(
                                                                client.id,
                                                            )
                                                        }
                                                        style={{
                                                            padding: "6px 12px",
                                                            background:
                                                                "#e74c3c",
                                                            color: "white",
                                                            border: "none",
                                                            borderRadius: "4px",
                                                            cursor: "pointer",
                                                            fontSize: "12px",
                                                        }}
                                                    >
                                                        Arquivar
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>

            {showModal && (
                <div
                    style={{
                        position: "fixed",
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: "rgba(0,0,0,0.5)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        zIndex: 1000,
                    }}
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "30px",
                            width: "90%",
                            maxWidth: "600px",
                            maxHeight: "90vh",
                            overflow: "auto",
                        }}
                    >
                        <h2
                            style={{
                                marginTop: 0,
                                marginBottom: "24px",
                                fontSize: "24px",
                                color: "#2c3e50",
                            }}
                        >
                            {modalMode === "create"
                                ? "Novo Cliente"
                                : "Editar Cliente"}
                        </h2>

                        <form onSubmit={handleSubmit}>
                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Nome *
                                </label>
                                <input
                                    type="text"
                                    value={formData.name}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            name: e.target.value,
                                        })
                                    }
                                    required
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>

                            <div
                                style={{
                                    display: "grid",
                                    gridTemplateColumns: "1fr 1fr",
                                    gap: "16px",
                                    marginBottom: "16px",
                                }}
                            >
                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        CPF/CNPJ
                                    </label>
                                    <input
                                        type="text"
                                        value={formData.registration_id}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                registration_id: e.target.value,
                                            })
                                        }
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>

                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Apelido/Nome Fantasia
                                    </label>
                                    <input
                                        type="text"
                                        value={formData.nickname}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                nickname: e.target.value,
                                            })
                                        }
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Data de Nascimento/Fundação
                                </label>
                                <input
                                    type="date"
                                    value={formData.birth_date}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            birth_date: e.target.value,
                                        })
                                    }
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>

                            <div
                                style={{
                                    display: "grid",
                                    gridTemplateColumns: "1fr 1fr",
                                    gap: "16px",
                                    marginBottom: "16px",
                                }}
                            >
                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Email
                                    </label>
                                    <input
                                        type="email"
                                        value={formData.email}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                email: e.target.value,
                                            })
                                        }
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>

                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Telefone
                                    </label>
                                    <input
                                        type="tel"
                                        value={formData.phone}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                phone: e.target.value,
                                            })
                                        }
                                        placeholder="+5511999999999"
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Endereço
                                </label>
                                <input
                                    type="text"
                                    value={formData.address}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            address: e.target.value,
                                        })
                                    }
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Preferência de Contato
                                </label>
                                <select
                                    value={formData.contact_preference}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            contact_preference: e.target.value,
                                        })
                                    }
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                >
                                    <option value="">Selecione...</option>
                                    <option value="whatsapp">WhatsApp</option>
                                    <option value="email">Email</option>
                                    <option value="phone">Telefone</option>
                                    <option value="sms">SMS</option>
                                    <option value="outros">Outros</option>
                                </select>
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Tags (separadas por vírgula)
                                </label>
                                <input
                                    type="text"
                                    value={formData.tags}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            tags: e.target.value,
                                        })
                                    }
                                    placeholder="vip, corporativo, etc"
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>

                            <div style={{ marginBottom: "24px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Observações
                                </label>
                                <textarea
                                    value={formData.notes}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            notes: e.target.value,
                                        })
                                    }
                                    rows={4}
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                        resize: "vertical",
                                    }}
                                />
                            </div>

                            <div
                                style={{
                                    display: "flex",
                                    gap: "12px",
                                    justifyContent: "flex-end",
                                }}
                            >
                                <button
                                    type="button"
                                    onClick={closeModal}
                                    style={{
                                        padding: "10px 24px",
                                        background: "white",
                                        color: "#7f8c8d",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                    }}
                                >
                                    Cancelar
                                </button>
                                <button
                                    type="submit"
                                    style={{
                                        padding: "10px 24px",
                                        background: "#27ae60",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {modalMode === "create"
                                        ? "Criar Cliente"
                                        : "Salvar Alterações"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showDependents && selectedClient && (
                <div
                    style={{
                        position: "fixed",
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: "rgba(0,0,0,0.5)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        zIndex: 1000,
                    }}
                >
                    <div
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "30px",
                            width: "90%",
                            maxWidth: "800px",
                            maxHeight: "90vh",
                            overflow: "auto",
                        }}
                    >
                        <div
                            style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                marginBottom: "24px",
                            }}
                        >
                            <h2
                                style={{
                                    margin: 0,
                                    fontSize: "24px",
                                    color: "#2c3e50",
                                }}
                            >
                                Dependentes de {selectedClient.name}
                            </h2>
                            <button
                                onClick={closeDependentsModal}
                                style={{
                                    background: "transparent",
                                    border: "none",
                                    fontSize: "24px",
                                    cursor: "pointer",
                                    color: "#7f8c8d",
                                }}
                            >
                                ×
                            </button>
                        </div>

                        <form
                            onSubmit={handleDependentSubmit}
                            style={{
                                marginBottom: "30px",
                                padding: "20px",
                                background: "#f8f9fa",
                                borderRadius: "8px",
                            }}
                        >
                            <h3
                                style={{
                                    marginTop: 0,
                                    marginBottom: "16px",
                                    fontSize: "18px",
                                    color: "#2c3e50",
                                }}
                            >
                                {selectedDependent
                                    ? "Editar Dependente"
                                    : "Adicionar Dependente"}
                            </h3>

                            <div
                                style={{
                                    display: "grid",
                                    gridTemplateColumns: "2fr 1fr",
                                    gap: "12px",
                                    marginBottom: "12px",
                                }}
                            >
                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Nome *
                                    </label>
                                    <input
                                        type="text"
                                        value={dependentForm.name}
                                        onChange={(e) =>
                                            setDependentForm({
                                                ...dependentForm,
                                                name: e.target.value,
                                            })
                                        }
                                        required
                                        style={{
                                            width: "100%",
                                            padding: "8px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>

                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Parentesco *
                                    </label>
                                    <input
                                        type="text"
                                        value={dependentForm.relationship}
                                        onChange={(e) =>
                                            setDependentForm({
                                                ...dependentForm,
                                                relationship: e.target.value,
                                            })
                                        }
                                        required
                                        placeholder="Filho, cônjuge..."
                                        style={{
                                            width: "100%",
                                            padding: "8px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>
                            </div>

                            <div
                                style={{
                                    display: "grid",
                                    gridTemplateColumns: "1fr 1fr",
                                    gap: "12px",
                                    marginBottom: "16px",
                                }}
                            >
                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Data de Nascimento
                                    </label>
                                    <input
                                        type="date"
                                        value={dependentForm.birth_date}
                                        onChange={(e) =>
                                            setDependentForm({
                                                ...dependentForm,
                                                birth_date: e.target.value,
                                            })
                                        }
                                        style={{
                                            width: "100%",
                                            padding: "8px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>

                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Telefone
                                    </label>
                                    <input
                                        type="tel"
                                        value={dependentForm.phone}
                                        onChange={(e) =>
                                            setDependentForm({
                                                ...dependentForm,
                                                phone: e.target.value,
                                            })
                                        }
                                        placeholder="+5511999999999"
                                        style={{
                                            width: "100%",
                                            padding: "8px",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    />
                                </div>
                            </div>

                            <div style={{ display: "flex", gap: "12px" }}>
                                {selectedDependent && (
                                    <button
                                        type="button"
                                        onClick={cancelDependentEdit}
                                        style={{
                                            padding: "8px 16px",
                                            background: "white",
                                            color: "#7f8c8d",
                                            border: "1px solid #ddd",
                                            borderRadius: "4px",
                                            cursor: "pointer",
                                            fontSize: "14px",
                                        }}
                                    >
                                        Cancelar Edição
                                    </button>
                                )}
                                <button
                                    type="submit"
                                    style={{
                                        padding: "8px 16px",
                                        background: "#27ae60",
                                        color: "white",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                    }}
                                >
                                    {selectedDependent
                                        ? "Salvar Alterações"
                                        : "Adicionar Dependente"}
                                </button>
                            </div>
                        </form>

                        {dependents.length === 0 ? (
                            <div
                                style={{
                                    padding: "40px",
                                    textAlign: "center",
                                    color: "#7f8c8d",
                                }}
                            >
                                Nenhum dependente cadastrado
                            </div>
                        ) : (
                            <div>
                                <h3
                                    style={{
                                        marginBottom: "16px",
                                        fontSize: "18px",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Lista de Dependentes
                                </h3>
                                <div
                                    style={{
                                        display: "flex",
                                        flexDirection: "column",
                                        gap: "12px",
                                    }}
                                >
                                    {dependents.map((dependent) => (
                                        <div
                                            key={dependent.id}
                                            style={{
                                                padding: "16px",
                                                border: "1px solid #ecf0f1",
                                                borderRadius: "8px",
                                                background:
                                                    selectedDependent?.id ===
                                                    dependent.id
                                                        ? "#e8f4f8"
                                                        : "white",
                                                display: "flex",
                                                justifyContent: "space-between",
                                                alignItems: "center",
                                            }}
                                        >
                                            <div>
                                                <div
                                                    style={{
                                                        fontSize: "16px",
                                                        fontWeight: "500",
                                                        color: "#2c3e50",
                                                        marginBottom: "4px",
                                                    }}
                                                >
                                                    {dependent.name}
                                                </div>
                                                <div
                                                    style={{
                                                        fontSize: "14px",
                                                        color: "#7f8c8d",
                                                    }}
                                                >
                                                    {dependent.relationship}
                                                    {dependent.birth_date &&
                                                        ` • ${formatDate(dependent.birth_date)}`}
                                                    {dependent.phone &&
                                                        ` • ${dependent.phone}`}
                                                </div>
                                            </div>
                                            <div
                                                style={{
                                                    display: "flex",
                                                    gap: "8px",
                                                }}
                                            >
                                                <button
                                                    onClick={() =>
                                                        editDependent(dependent)
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#3498db",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "12px",
                                                    }}
                                                >
                                                    Editar
                                                </button>
                                                <button
                                                    onClick={() =>
                                                        deleteDependent(
                                                            dependent.id,
                                                        )
                                                    }
                                                    style={{
                                                        padding: "6px 12px",
                                                        background: "#e74c3c",
                                                        color: "white",
                                                        border: "none",
                                                        borderRadius: "4px",
                                                        cursor: "pointer",
                                                        fontSize: "12px",
                                                    }}
                                                >
                                                    Deletar
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div
                            style={{
                                marginTop: "24px",
                                paddingTop: "20px",
                                borderTop: "1px solid #ecf0f1",
                            }}
                        >
                            <button
                                onClick={closeDependentsModal}
                                style={{
                                    padding: "10px 24px",
                                    background: "#7f8c8d",
                                    color: "white",
                                    border: "none",
                                    borderRadius: "4px",
                                    cursor: "pointer",
                                    fontSize: "14px",
                                }}
                            >
                                Fechar
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
