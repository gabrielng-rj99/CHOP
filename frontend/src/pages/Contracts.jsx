import React, { useState, useEffect } from "react";

export default function Contracts({ token, apiUrl }) {
    const [contracts, setContracts] = useState([]);
    const [clients, setClients] = useState([]);
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [dependents, setDependents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [filter, setFilter] = useState("all");
    const [searchTerm, setSearchTerm] = useState("");
    const [showModal, setShowModal] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [selectedContract, setSelectedContract] = useState(null);
    const [formData, setFormData] = useState({
        model: "",
        product_key: "",
        start_date: "",
        end_date: "",
        client_id: "",
        dependent_id: "",
        category_id: "",
        line_id: "",
        additional_data: "",
    });

    useEffect(() => {
        loadContracts();
        loadClients();
        loadCategories();
    }, []);

    const loadContracts = async () => {
        setLoading(true);
        setError("");

        try {
            const response = await fetch(`${apiUrl}/api/contracts`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            });

            if (!response.ok) {
                throw new Error("Erro ao carregar contratos");
            }

            const data = await response.json();
            setContracts(data.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const loadClients = async () => {
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
            console.error("Erro ao carregar clientes:", err);
        }
    };

    const loadCategories = async () => {
        try {
            const response = await fetch(`${apiUrl}/api/categories`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            });

            if (!response.ok) {
                throw new Error("Erro ao carregar categorias");
            }

            const data = await response.json();
            setCategories(data.data || []);
        } catch (err) {
            console.error("Erro ao carregar categorias:", err);
        }
    };

    const loadLines = async (categoryId) => {
        try {
            const response = await fetch(
                `${apiUrl}/api/categories/${categoryId}/lines`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                },
            );

            if (!response.ok) {
                throw new Error("Erro ao carregar linhas");
            }

            const data = await response.json();
            setLines(data.data || []);
        } catch (err) {
            console.error("Erro ao carregar linhas:", err);
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
            console.error("Erro ao carregar dependentes:", err);
        }
    };

    const createContract = async () => {
        try {
            const payload = {
                model: formData.model,
                product_key: formData.product_key,
                start_date: formData.start_date,
                end_date: formData.end_date,
                client_id: formData.client_id,
                dependent_id: formData.dependent_id || null,
                category_id: formData.category_id,
                line_id: formData.line_id,
                additional_data: formData.additional_data || null,
            };

            const response = await fetch(`${apiUrl}/api/contracts`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Erro ao criar contrato");
            }

            await loadContracts();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateContract = async () => {
        try {
            const payload = {
                model: formData.model,
                product_key: formData.product_key,
                start_date: formData.start_date,
                end_date: formData.end_date,
                client_id: formData.client_id,
                dependent_id: formData.dependent_id || null,
                category_id: formData.category_id,
                line_id: formData.line_id,
                additional_data: formData.additional_data || null,
            };

            const response = await fetch(
                `${apiUrl}/api/contracts/${selectedContract.id}`,
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
                    errorData.error || "Erro ao atualizar contrato",
                );
            }

            await loadContracts();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const archiveContract = async (contractId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este contrato?"))
            return;

        try {
            const response = await fetch(
                `${apiUrl}/api/contracts/${contractId}/archive`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                },
            );

            if (!response.ok) {
                throw new Error("Erro ao arquivar contrato");
            }

            await loadContracts();
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveContract = async (contractId) => {
        try {
            const response = await fetch(
                `${apiUrl}/api/contracts/${contractId}/unarchive`,
                {
                    method: "PUT",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                },
            );

            if (!response.ok) {
                throw new Error("Erro ao desarquivar contrato");
            }

            await loadContracts();
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData({
            model: "",
            product_key: "",
            start_date: "",
            end_date: "",
            client_id: "",
            dependent_id: "",
            category_id: "",
            line_id: "",
            additional_data: "",
        });
        setDependents([]);
        setLines([]);
        setShowModal(true);
    };

    const openEditModal = async (contract) => {
        setModalMode("edit");
        setSelectedContract(contract);

        if (contract.client_id) {
            await loadDependents(contract.client_id);
        }
        if (contract.category_id) {
            await loadLines(contract.category_id);
        }

        setFormData({
            model: contract.model || "",
            product_key: contract.product_key || "",
            start_date: contract.start_date
                ? contract.start_date.split("T")[0]
                : "",
            end_date: contract.end_date ? contract.end_date.split("T")[0] : "",
            client_id: contract.client_id || "",
            dependent_id: contract.dependent_id || "",
            category_id: contract.category_id || "",
            line_id: contract.line_id || "",
            additional_data: contract.additional_data || "",
        });
        setShowModal(true);
    };

    const openDetailsModal = (contract) => {
        setSelectedContract(contract);
        setShowDetailsModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedContract(null);
        setDependents([]);
        setLines([]);
        setError("");
    };

    const closeDetailsModal = () => {
        setShowDetailsModal(false);
        setSelectedContract(null);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            createContract();
        } else {
            updateContract();
        }
    };

    const handleClientChange = async (clientId) => {
        setFormData({
            ...formData,
            client_id: clientId,
            dependent_id: "",
        });
        setDependents([]);
        if (clientId) {
            await loadDependents(clientId);
        }
    };

    const handleCategoryChange = async (categoryId) => {
        setFormData({
            ...formData,
            category_id: categoryId,
            line_id: "",
        });
        setLines([]);
        if (categoryId) {
            await loadLines(categoryId);
        }
    };

    const getContractStatus = (contract) => {
        const endDate = new Date(contract.end_date);
        const now = new Date();
        const daysUntilExpiration = Math.ceil(
            (endDate - now) / (1000 * 60 * 60 * 24),
        );

        if (daysUntilExpiration < 0) {
            return { status: "Expirado", color: "#e74c3c" };
        } else if (daysUntilExpiration <= 30) {
            return { status: "Expirando", color: "#f39c12" };
        } else {
            return { status: "Ativo", color: "#27ae60" };
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        const date = new Date(dateString);
        return date.toLocaleDateString("pt-BR");
    };

    const getClientName = (clientId) => {
        const client = clients.find((c) => c.id === clientId);
        return client ? client.name : "-";
    };

    const getCategoryName = (categoryId) => {
        const category = categories.find((c) => c.id === categoryId);
        return category ? category.name : "-";
    };

    const filteredContracts = contracts.filter((contract) => {
        const isArchived = !!contract.archived_at;

        if (filter === "archived") {
            return isArchived;
        }

        if (isArchived) return false;

        const status = getContractStatus(contract);

        const matchesFilter =
            filter === "all" ||
            (filter === "active" && status.status === "Ativo") ||
            (filter === "expiring" && status.status === "Expirando") ||
            (filter === "expired" && status.status === "Expirado");

        const matchesSearch =
            searchTerm === "" ||
            contract.model?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            contract.product_key
                ?.toLowerCase()
                .includes(searchTerm.toLowerCase()) ||
            getClientName(contract.client_id)
                ?.toLowerCase()
                .includes(searchTerm.toLowerCase());

        return matchesFilter && matchesSearch;
    });

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "60px" }}>
                <div style={{ fontSize: "18px", color: "#7f8c8d" }}>
                    Carregando contratos...
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
                    Contratos
                </h1>
                <div style={{ display: "flex", gap: "12px" }}>
                    <button
                        onClick={loadContracts}
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
                        + Novo Contrato
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
                    Todos ({contracts.filter((c) => !c.archived_at).length})
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
                    onClick={() => setFilter("expiring")}
                    style={{
                        padding: "8px 16px",
                        background: filter === "expiring" ? "#f39c12" : "white",
                        color: filter === "expiring" ? "white" : "#2c3e50",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                    }}
                >
                    Expirando
                </button>
                <button
                    onClick={() => setFilter("expired")}
                    style={{
                        padding: "8px 16px",
                        background: filter === "expired" ? "#e74c3c" : "white",
                        color: filter === "expired" ? "white" : "#2c3e50",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                    }}
                >
                    Expirados
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
                    placeholder="Buscar por modelo, chave, cliente..."
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
                {filteredContracts.length === 0 ? (
                    <div
                        style={{
                            padding: "40px",
                            textAlign: "center",
                            color: "#7f8c8d",
                        }}
                    >
                        Nenhum contrato encontrado
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
                                    MODELO
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
                                    CLIENTE
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
                                    CHAVE DO PRODUTO
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
                                    VALIDADE
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
                            {filteredContracts.map((contract) => {
                                const status = getContractStatus(contract);
                                const isArchived = !!contract.archived_at;
                                return (
                                    <tr
                                        key={contract.id}
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
                                            {contract.model}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {getClientName(contract.client_id)}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                                fontFamily: "monospace",
                                            }}
                                        >
                                            {contract.product_key}
                                        </td>
                                        <td
                                            style={{
                                                padding: "16px",
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {formatDate(contract.start_date)} -{" "}
                                            {formatDate(contract.end_date)}
                                        </td>
                                        <td style={{ padding: "16px" }}>
                                            <span
                                                style={{
                                                    display: "inline-block",
                                                    padding: "4px 12px",
                                                    borderRadius: "12px",
                                                    fontSize: "12px",
                                                    fontWeight: "600",
                                                    background: isArchived
                                                        ? "#95a5a620"
                                                        : status.color + "20",
                                                    color: isArchived
                                                        ? "#95a5a6"
                                                        : status.color,
                                                }}
                                            >
                                                {isArchived
                                                    ? "Arquivado"
                                                    : status.status}
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
                                                        openDetailsModal(
                                                            contract,
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
                                                    Ver
                                                </button>
                                                <button
                                                    onClick={() =>
                                                        openEditModal(contract)
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
                                                {isArchived ? (
                                                    <button
                                                        onClick={() =>
                                                            unarchiveContract(
                                                                contract.id,
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
                                                            archiveContract(
                                                                contract.id,
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
                            maxWidth: "700px",
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
                                ? "Novo Contrato"
                                : "Editar Contrato"}
                        </h2>

                        <form onSubmit={handleSubmit}>
                            <div
                                style={{
                                    padding: "12px",
                                    background: "#e8f4f8",
                                    borderRadius: "4px",
                                    marginBottom: "20px",
                                    fontSize: "13px",
                                    color: "#2c3e50",
                                }}
                            >
                                <strong>
                                    Campos obrigatórios marcados com *
                                </strong>
                                <br />
                                Os demais campos são opcionais
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                        color: "#2c3e50",
                                    }}
                                >
                                    Cliente{" "}
                                    <span style={{ color: "#e74c3c" }}>*</span>
                                </label>
                                <select
                                    value={formData.client_id}
                                    onChange={(e) =>
                                        handleClientChange(e.target.value)
                                    }
                                    required
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "2px solid #3498db",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                >
                                    <option value="">
                                        Selecione um cliente
                                    </option>
                                    {clients.map((client) => (
                                        <option
                                            key={client.id}
                                            value={client.id}
                                        >
                                            {client.name}
                                        </option>
                                    ))}
                                </select>
                            </div>

                            {formData.client_id && (
                                <div style={{ marginBottom: "16px" }}>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "500",
                                            color: "#7f8c8d",
                                        }}
                                    >
                                        Dependente{" "}
                                        <span style={{ fontSize: "12px" }}>
                                            (opcional)
                                        </span>
                                    </label>
                                    <select
                                        value={formData.dependent_id}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                dependent_id: e.target.value,
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
                                        <option value="">Nenhum</option>
                                        {dependents.map((dependent) => (
                                            <option
                                                key={dependent.id}
                                                value={dependent.id}
                                            >
                                                {dependent.name} (
                                                {dependent.relationship})
                                            </option>
                                        ))}
                                    </select>
                                </div>
                            )}

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
                                            fontWeight: "600",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Categoria{" "}
                                        <span style={{ color: "#e74c3c" }}>
                                            *
                                        </span>
                                    </label>
                                    <select
                                        value={formData.category_id}
                                        onChange={(e) =>
                                            handleCategoryChange(e.target.value)
                                        }
                                        required
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "2px solid #3498db",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                        }}
                                    >
                                        <option value="">
                                            Selecione uma categoria
                                        </option>
                                        {categories.map((category) => (
                                            <option
                                                key={category.id}
                                                value={category.id}
                                            >
                                                {category.name}
                                            </option>
                                        ))}
                                    </select>
                                </div>

                                <div>
                                    <label
                                        style={{
                                            display: "block",
                                            marginBottom: "6px",
                                            fontSize: "14px",
                                            fontWeight: "600",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Linha{" "}
                                        <span style={{ color: "#e74c3c" }}>
                                            *
                                        </span>
                                    </label>
                                    <select
                                        value={formData.line_id}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                line_id: e.target.value,
                                            })
                                        }
                                        required
                                        disabled={!formData.category_id}
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "2px solid #3498db",
                                            borderRadius: "4px",
                                            fontSize: "14px",
                                            boxSizing: "border-box",
                                            opacity: formData.category_id
                                                ? 1
                                                : 0.5,
                                        }}
                                    >
                                        <option value="">
                                            {formData.category_id
                                                ? "Selecione uma linha"
                                                : "Selecione categoria primeiro"}
                                        </option>
                                        {lines.map((line) => (
                                            <option
                                                key={line.id}
                                                value={line.id}
                                            >
                                                {line.line}
                                            </option>
                                        ))}
                                    </select>
                                </div>
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
                                            fontWeight: "600",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Data de Início{" "}
                                        <span style={{ color: "#e74c3c" }}>
                                            *
                                        </span>
                                    </label>
                                    <input
                                        type="date"
                                        value={formData.start_date}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                start_date: e.target.value,
                                            })
                                        }
                                        required
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "2px solid #3498db",
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
                                            fontWeight: "600",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        Data de Término{" "}
                                        <span style={{ color: "#e74c3c" }}>
                                            *
                                        </span>
                                    </label>
                                    <input
                                        type="date"
                                        value={formData.end_date}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                end_date: e.target.value,
                                            })
                                        }
                                        required
                                        style={{
                                            width: "100%",
                                            padding: "10px",
                                            border: "2px solid #3498db",
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
                                            color: "#7f8c8d",
                                        }}
                                    >
                                        Modelo{" "}
                                        <span style={{ fontSize: "12px" }}>
                                            (opcional)
                                        </span>
                                    </label>
                                    <input
                                        type="text"
                                        value={formData.model}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                model: e.target.value,
                                            })
                                        }
                                        placeholder="Ex: Premium, Básico..."
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
                                            color: "#7f8c8d",
                                        }}
                                    >
                                        Chave do Produto{" "}
                                        <span style={{ fontSize: "12px" }}>
                                            (opcional)
                                        </span>
                                    </label>
                                    <input
                                        type="text"
                                        value={formData.product_key}
                                        onChange={(e) =>
                                            setFormData({
                                                ...formData,
                                                product_key: e.target.value,
                                            })
                                        }
                                        placeholder="Ex: XXXX-XXXX-XXXX..."
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

                            <div style={{ marginBottom: "24px" }}>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#7f8c8d",
                                    }}
                                >
                                    Dados Adicionais{" "}
                                    <span style={{ fontSize: "12px" }}>
                                        (opcional - JSON)
                                    </span>
                                </label>
                                <textarea
                                    value={formData.additional_data}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            additional_data: e.target.value,
                                        })
                                    }
                                    rows={3}
                                    placeholder='{"campo": "valor"}'
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ddd",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                        fontFamily: "monospace",
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
                                        ? "Criar Contrato"
                                        : "Salvar Alterações"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showDetailsModal && selectedContract && (
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
                                Detalhes do Contrato
                            </h2>
                            <button
                                onClick={closeDetailsModal}
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

                        <div
                            style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: "16px",
                            }}
                        >
                            <div>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    MODELO
                                </div>
                                <div
                                    style={{
                                        fontSize: "16px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    {selectedContract.model}
                                </div>
                            </div>

                            <div>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    CHAVE DO PRODUTO
                                </div>
                                <div
                                    style={{
                                        fontSize: "16px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                        fontFamily: "monospace",
                                    }}
                                >
                                    {selectedContract.product_key}
                                </div>
                            </div>

                            <div
                                style={{
                                    display: "grid",
                                    gridTemplateColumns: "1fr 1fr",
                                    gap: "16px",
                                }}
                            >
                                <div>
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginBottom: "4px",
                                        }}
                                    >
                                        DATA INÍCIO
                                    </div>
                                    <div
                                        style={{
                                            fontSize: "16px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        {formatDate(
                                            selectedContract.start_date,
                                        )}
                                    </div>
                                </div>
                                <div>
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginBottom: "4px",
                                        }}
                                    >
                                        DATA FIM
                                    </div>
                                    <div
                                        style={{
                                            fontSize: "16px",
                                            fontWeight: "500",
                                            color: "#2c3e50",
                                        }}
                                    >
                                        {formatDate(selectedContract.end_date)}
                                    </div>
                                </div>
                            </div>

                            <div>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    CLIENTE
                                </div>
                                <div
                                    style={{
                                        fontSize: "16px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    {getClientName(selectedContract.client_id)}
                                </div>
                            </div>

                            <div>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    CATEGORIA
                                </div>
                                <div
                                    style={{
                                        fontSize: "16px",
                                        fontWeight: "500",
                                        color: "#2c3e50",
                                    }}
                                >
                                    {getCategoryName(
                                        selectedContract.category_id,
                                    )}
                                </div>
                            </div>

                            {selectedContract.additional_data && (
                                <div>
                                    <div
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginBottom: "4px",
                                        }}
                                    >
                                        DADOS ADICIONAIS
                                    </div>
                                    <div
                                        style={{
                                            fontSize: "14px",
                                            color: "#2c3e50",
                                            fontFamily: "monospace",
                                            background: "#f8f9fa",
                                            padding: "12px",
                                            borderRadius: "4px",
                                        }}
                                    >
                                        {selectedContract.additional_data}
                                    </div>
                                </div>
                            )}

                            <div>
                                <div
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginBottom: "4px",
                                    }}
                                >
                                    STATUS
                                </div>
                                <div>
                                    {(() => {
                                        const status =
                                            getContractStatus(selectedContract);
                                        return (
                                            <span
                                                style={{
                                                    display: "inline-block",
                                                    padding: "6px 16px",
                                                    borderRadius: "12px",
                                                    fontSize: "14px",
                                                    fontWeight: "600",
                                                    background:
                                                        status.color + "20",
                                                    color: status.color,
                                                }}
                                            >
                                                {status.status}
                                            </span>
                                        );
                                    })()}
                                </div>
                            </div>
                        </div>

                        <div
                            style={{
                                marginTop: "24px",
                                paddingTop: "20px",
                                borderTop: "1px solid #ecf0f1",
                            }}
                        >
                            <button
                                onClick={closeDetailsModal}
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
