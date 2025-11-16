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
import DependentsPanel from "../components/clients/DependentsPanel";
import DependentModal from "../components/clients/DependentModal";
import "./Clients.css";

export default function Clients({ token, apiUrl, onTokenExpired }) {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [modalError, setModalError] = useState("");
    const [dependentModalError, setDependentModalError] = useState("");
    const [filter, setFilter] = useState("active");
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedClient, setSelectedClient] = useState(null);
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [showDependentsPanel, setShowDependentsPanel] = useState(false);
    const [showDependentModal, setShowDependentModal] = useState(false);
    const [dependentModalMode, setDependentModalMode] = useState("create");
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
            await clientsApi.loadClients(apiUrl, token, setClients, setError, onTokenExpired);
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
                onTokenExpired,
            );
            setDependents(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const createClient = async () => {
        setModalError("");
        try {
            await clientsApi.createClient(apiUrl, token, formData, onTokenExpired);
            await loadClients();
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const updateClient = async () => {
        setModalError("");
        try {
            await clientsApi.updateClient(
                apiUrl,
                token,
                selectedClient.id,
                formData,
                onTokenExpired,
            );
            await loadClients();
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const archiveClient = async (clientId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este cliente?"))
            return;

        try {
            await clientsApi.archiveClient(apiUrl, token, clientId, onTokenExpired);
            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveClient = async (clientId) => {
        try {
            await clientsApi.unarchiveClient(apiUrl, token, clientId, onTokenExpired);
            await loadClients();
        } catch (err) {
            setError(err.message);
        }
    };

    const createDependent = async () => {
        setDependentModalError("");
        try {
            await clientsApi.createDependent(
                apiUrl,
                token,
                selectedClient.id,
                dependentForm,
                onTokenExpired,
            );
            await loadDependents(selectedClient.id);
            closeDependentModal();
        } catch (err) {
            setDependentModalError(err.message);
        }
    };

    const updateDependent = async () => {
        setDependentModalError("");
        try {
            await clientsApi.updateDependent(
                apiUrl,
                token,
                selectedDependent.id,
                dependentForm,
                onTokenExpired,
            );
            await loadDependents(selectedClient.id);
            closeDependentModal();
        } catch (err) {
            setDependentModalError(err.message);
        }
    };

    const deleteDependent = async (dependentId) => {
        if (!window.confirm("Tem certeza que deseja deletar este dependente?"))
            return;

        try {
            await clientsApi.deleteDependent(apiUrl, token, dependentId, onTokenExpired);
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

    const openDependentsPanel = async (client) => {
        setSelectedClient(client);
        await loadDependents(client.id);
        setShowDependentsPanel(true);
    };

    const closeDependentsPanel = () => {
        setShowDependentsPanel(false);
        setSelectedClient(null);
        setDependents([]);
    };

    const openCreateDependentModal = () => {
        setDependentModalMode("create");
        setSelectedDependent(null);
        setDependentForm(getInitialDependentForm());
        setShowDependentModal(true);
    };

    const openEditDependentModal = (dependent) => {
        setDependentModalMode("edit");
        setSelectedDependent(dependent);
        setDependentForm(formatDependentForEdit(dependent));
        setShowDependentModal(true);
    };

    const closeDependentModal = () => {
        setShowDependentModal(false);
        setSelectedDependent(null);
        setDependentForm(getInitialDependentForm());
        setDependentModalError("");
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedClient(null);
        setModalError("");
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
        if (dependentModalMode === "create") {
            createDependent();
        } else {
            updateDependent();
        }
    };

    function compareAlphaNum(a, b) {
        const regex = /(.*?)(\d+)$/;
        const aVal = (a.name || "").trim();
        const bVal = (b.name || "").trim();
        const aMatch = aVal.match(regex);
        const bMatch = bVal.match(regex);

        if (aMatch && bMatch && aMatch[1] === bMatch[1]) {
            return parseInt(aMatch[2], 10) - parseInt(bMatch[2], 10);
        }
        return aVal.localeCompare(bVal);
    }

    const filteredClients = filterClients(
        [...clients].sort(compareAlphaNum),
        filter,
        searchTerm,
    );

    if (loading) {
        return (
            <div className="clients-loading">
                <div className="clients-loading-text">
                    Carregando clientes...
                </div>
            </div>
        );
    }

    return (
        <div className="clients-container">
            <div className="clients-header">
                <h1 className="clients-title">Clientes</h1>
                <div className="clients-button-group">
                    <button
                        onClick={loadClients}
                        className="clients-button-secondary"
                    >
                        Atualizar
                    </button>
                    <button
                        onClick={openCreateModal}
                        className="clients-button"
                    >
                        + Novo Cliente
                    </button>
                </div>
            </div>

            {error && !showModal && (
                <div className="clients-error">{error}</div>
            )}

            <div className="clients-filters">
                <button
                    onClick={() => setFilter("active")}
                    className={`clients-filter-button ${filter === "active" ? "active-active" : ""}`}
                >
                    Ativos
                </button>
                <button
                    onClick={() => setFilter("inactive")}
                    className={`clients-filter-button ${filter === "inactive" ? "active-inactive" : ""}`}
                >
                    Inativos
                </button>
                <button
                    onClick={() => setFilter("archived")}
                    className={`clients-filter-button ${filter === "archived" ? "active-archived" : ""}`}
                >
                    Arquivados
                </button>
                <button
                    onClick={() => setFilter("all")}
                    className={`clients-filter-button ${filter === "all" ? "active-all" : ""}`}
                >
                    Todos ({clients.length})
                </button>

                <input
                    type="text"
                    placeholder="Buscar por nome, apelido, CPF/CNPJ, email..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="clients-search-input"
                />
            </div>

            <div className="clients-table-wrapper">
                {/* <div className="clients-table-header">
                    <h2 className="clients-table-header-title">Clientes</h2>
                </div>*/}
                <ClientsTable
                    filteredClients={filteredClients}
                    openEditModal={openEditModal}
                    openDependentsPanel={openDependentsPanel}
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
                error={modalError}
            />

            {showDependentsPanel && (
                <DependentsPanel
                    selectedClient={selectedClient}
                    dependents={dependents}
                    onCreateDependent={openCreateDependentModal}
                    onEditDependent={openEditDependentModal}
                    onDeleteDependent={deleteDependent}
                    onClose={closeDependentsPanel}
                />
            )}

            <DependentModal
                showModal={showDependentModal}
                modalMode={dependentModalMode}
                dependentForm={dependentForm}
                setDependentForm={setDependentForm}
                onSubmit={handleDependentSubmit}
                onClose={closeDependentModal}
                error={dependentModalError}
            />
        </div>
    );
}
