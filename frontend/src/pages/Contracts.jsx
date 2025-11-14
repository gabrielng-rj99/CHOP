import React, { useState, useEffect } from "react";
import { contractsApi } from "../api/contractsApi";
import {
    getInitialFormData,
    formatContractForEdit,
    filterContracts,
    formatDate,
    getContractStatus,
    getClientName,
    getCategoryName,
} from "../utils/contractHelpers";
import ContractsTable from "../components/contracts/ContractsTable";
import ContractModal from "../components/contracts/ContractModal";

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
    const [formData, setFormData] = useState(getInitialFormData());

    useEffect(() => {
        loadInitialData();
    }, []);

    const loadInitialData = async () => {
        setLoading(true);
        try {
            await Promise.all([
                loadContracts(),
                loadClients(),
                loadCategories(),
            ]);
        } finally {
            setLoading(false);
        }
    };

    const loadContracts = async () => {
        setError("");
        try {
            const data = await contractsApi.loadContracts(apiUrl, token);
            setContracts(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const loadClients = async () => {
        try {
            const data = await contractsApi.loadClients(apiUrl, token);
            setClients(data);
        } catch (err) {
            console.error("Erro ao carregar clientes:", err);
        }
    };

    const loadCategories = async () => {
        try {
            const data = await contractsApi.loadCategories(apiUrl, token);
            setCategories(data);
        } catch (err) {
            console.error("Erro ao carregar categorias:", err);
        }
    };

    const loadLines = async (categoryId) => {
        try {
            const data = await contractsApi.loadLines(
                apiUrl,
                token,
                categoryId,
            );
            setLines(data);
        } catch (err) {
            console.error("Erro ao carregar linhas:", err);
        }
    };

    const loadDependents = async (clientId) => {
        try {
            const data = await contractsApi.loadDependents(
                apiUrl,
                token,
                clientId,
            );
            setDependents(data);
        } catch (err) {
            console.error("Erro ao carregar dependentes:", err);
        }
    };

    const handleCreateContract = async () => {
        try {
            await contractsApi.createContract(apiUrl, token, formData);
            await loadContracts();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdateContract = async () => {
        try {
            await contractsApi.updateContract(
                apiUrl,
                token,
                selectedContract.id,
                formData,
            );
            await loadContracts();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleArchiveContract = async (contractId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este contrato?"))
            return;

        try {
            await contractsApi.archiveContract(apiUrl, token, contractId);
            await loadContracts();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveContract = async (contractId) => {
        try {
            await contractsApi.unarchiveContract(apiUrl, token, contractId);
            await loadContracts();
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData(getInitialFormData());
        setLines([]);
        setDependents([]);
        setShowModal(true);
    };

    const openEditModal = (contract) => {
        setModalMode("edit");
        setSelectedContract(contract);
        setFormData(formatContractForEdit(contract));
        setShowModal(true);

        if (contract.client_id) {
            loadDependents(contract.client_id);
        }
        if (contract.line?.category_id) {
            loadLines(contract.line.category_id);
        }
    };

    const openDetailsModal = (contract) => {
        setSelectedContract(contract);
        setShowDetailsModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedContract(null);
        setFormData(getInitialFormData());
        setLines([]);
        setDependents([]);
        setError("");
    };

    const closeDetailsModal = () => {
        setShowDetailsModal(false);
        setSelectedContract(null);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            handleCreateContract();
        } else {
            handleUpdateContract();
        }
    };

    const handleCategoryChange = (categoryId) => {
        if (categoryId) {
            loadLines(categoryId);
        } else {
            setLines([]);
        }
    };

    const handleClientChange = (clientId) => {
        if (clientId) {
            loadDependents(clientId);
        } else {
            setDependents([]);
        }
    };

    const filteredContracts = filterContracts(
        contracts,
        filter,
        searchTerm,
        clients,
        categories,
    );

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
                <ContractsTable
                    filteredContracts={filteredContracts}
                    clients={clients}
                    categories={categories}
                    onViewDetails={openDetailsModal}
                    onEdit={openEditModal}
                    onArchive={handleArchiveContract}
                    onUnarchive={handleUnarchiveContract}
                />
            </div>

            <ContractModal
                showModal={showModal}
                modalMode={modalMode}
                formData={formData}
                setFormData={setFormData}
                clients={clients}
                categories={categories}
                lines={lines}
                dependents={dependents}
                onSubmit={handleSubmit}
                onClose={closeModal}
                onCategoryChange={handleCategoryChange}
                onClientChange={handleClientChange}
            />

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
                        padding: "20px",
                    }}
                    onClick={closeDetailsModal}
                >
                    <div
                        onClick={(e) => e.stopPropagation()}
                        style={{
                            background: "white",
                            borderRadius: "8px",
                            padding: "32px",
                            width: "90%",
                            maxWidth: "600px",
                            maxHeight: "90vh",
                            overflowY: "auto",
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
                            Detalhes do Contrato
                        </h2>

                        <div style={{ display: "grid", gap: "16px" }}>
                            <DetailRow
                                label="Modelo"
                                value={selectedContract.model || "-"}
                            />
                            <DetailRow
                                label="Chave do Produto"
                                value={selectedContract.product_key || "-"}
                            />
                            <DetailRow
                                label="Cliente"
                                value={getClientName(selectedContract.client_id, clients)}
                            />
                            {selectedContract.dependent && (
                                <DetailRow
                                    label="Dependente"
                                    value={selectedContract.dependent.name}
                                />
                            )}
                            <DetailRow
                                label="Categoria"
                                value={getCategoryName(selectedContract.line_id, categories)}
                            />
                            <DetailRow
                                label="Linha"
                                value={selectedContract.line?.line || "-"}
                            />
                            <DetailRow
                                label="Data de Início"
                                value={formatDate(selectedContract.start_date)}
                            />
                            <DetailRow
                                label="Data de Vencimento"
                                value={formatDate(selectedContract.end_date)}
                            />
                        </div>

                        <div
                            style={{
                                marginTop: "32px",
                                display: "flex",
                                justifyContent: "flex-end",
                            }}
                        >
                            <button
                                onClick={closeDetailsModal}
                                style={{
                                    padding: "10px 24px",
                                    background: "#3498db",
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

function DetailRow({ label, value }) {
    return (
        <div
            style={{
                padding: "12px",
                background: "#f8f9fa",
                borderRadius: "6px",
            }}
        >
            <div
                style={{
                    fontSize: "12px",
                    color: "#7f8c8d",
                    marginBottom: "4px",
                    fontWeight: "600",
                }}
            >
                {label}
            </div>
            <div
                style={{
                    fontSize: "14px",
                    color: "#2c3e50",
                }}
            >
                {value}
            </div>
        </div>
    );
}
