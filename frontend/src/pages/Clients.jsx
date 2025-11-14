import React, { useState, useEffect } from "react";
import { clientsApi } from "../api/clientsApi";
import {
    filterClients,
    formatClientForEdit,
    formatDependentForEdit,
    getInitialFormData,
    getInitialDependentForm,
} from "../utils/clientHelpers";
import ClientModal from "../components/clients/ClientModal";
import ClientsTable from "../components/clients/ClientsTable";
import DependentsModal from "../components/clients/DependentsModal";

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
    const [formData, setFormData] = useState(getInitialFormData());
    const [dependentForm, setDependentForm] = useState(
        getInitialDependentForm(),
    );

    useEffect(() => {
        loadClients();
    }, []);

    const loadClients = async () => {
        setLoading(true);
        setError("");
        try {
            await clientsApi.loadClients(apiUrl, token, setClients, setError);
        } finally {
            setLoading(false);
        }
    };

    const loadDependents = async (clientId) => {
        try {
            const data = await clientsApi.loadDependents(
                apiUrl,
                token,
                clientId,
            );
            setDependents(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const createClient = async () => {
        try {
            await clientsApi.createClient(apiUrl, token, formData);
            await loadClients();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const updateClient = async () => {
        try {
            await clientsApi.updateClient(
                apiUrl,
                token,
                selectedClient.id,
                formData,
            );
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
            await clientsApi.archiveClient(apiUrl, token, clientId);
            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveClient = async (clientId) => {
        try {
            await clientsApi.unarchiveClient(apiUrl, token, clientId);
            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const createDependent = async () => {
        try {
            await clientsApi.createDependent(
                apiUrl,
                token,
                selectedClient.id,
                dependentForm,
            );
            await loadDependents(selectedClient.id);
            setDependentForm(getInitialDependentForm());
            setSelectedDependent(null);
        } catch (err) {
            setError(err.message);
        }
    };

    const updateDependent = async () => {
        try {
            await clientsApi.updateDependent(
                apiUrl,
                token,
                selectedDependent.id,
                dependentForm,
            );
            await loadDependents(selectedClient.id);
            setDependentForm(getInitialDependentForm());
            setSelectedDependent(null);
        } catch (err) {
            setError(err.message);
        }
    };

    const deleteDependent = async (dependentId) => {
        if (!window.confirm("Tem certeza que deseja deletar este dependente?"))
            return;

        try {
            await clientsApi.deleteDependent(apiUrl, token, dependentId);
            await loadDependents(selectedClient.id);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreateModal = () => {
        setModalMode("create");
        setFormData(getInitialFormData());
        setShowModal(true);
    };

    const openEditModal = (client) => {
        setModalMode("edit");
        setSelectedClient(client);
        setFormData(formatClientForEdit(client));
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
        setDependentForm(getInitialDependentForm());
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
        setDependentForm(formatDependentForEdit(dependent));
    };

    const cancelDependentEdit = () => {
        setSelectedDependent(null);
        setDependentForm(getInitialDependentForm());
    };

    const filteredClients = filterClients(clients, filter, searchTerm);

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
                <ClientsTable
                    filteredClients={filteredClients}
                    openEditModal={openEditModal}
                    openDependentsModal={openDependentsModal}
                    archiveClient={archiveClient}
                    unarchiveClient={unarchiveClient}
                />
            </div>

            <ClientModal
                showModal={showModal}
                modalMode={modalMode}
                formData={formData}
                setFormData={setFormData}
                handleSubmit={handleSubmit}
                closeModal={closeModal}
            />

            <DependentsModal
                showDependents={showDependents}
                selectedClient={selectedClient}
                dependents={dependents}
                dependentForm={dependentForm}
                setDependentForm={setDependentForm}
                selectedDependent={selectedDependent}
                handleDependentSubmit={handleDependentSubmit}
                editDependent={editDependent}
                deleteDependent={deleteDependent}
                cancelDependentEdit={cancelDependentEdit}
                closeDependentsModal={closeDependentsModal}
            />
        </div>
    );
}
