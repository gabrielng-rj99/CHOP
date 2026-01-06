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

import React, { useState, useEffect, useRef } from "react";
import { useConfig } from "../contexts/ConfigContext";
import { useData } from "../contexts/DataContext";
import { clientsApi } from "../api/clientsApi";
import { useUrlState } from "../hooks/useUrlState";
import {
    filterClients,
    formatClientForEdit,
    formatAffiliateForEdit,
    getInitialFormData,
    getInitialAffiliateForm,
} from "../utils/clientHelpers";
import ClientModal from "../components/clients/ClientModal";
import ClientsTable from "../components/clients/ClientsTable";
import AffiliatesPanel from "../components/clients/AffiliatesPanel";
import AffiliateModal from "../components/clients/AffiliateModal";
import PrimaryButton from "../components/common/PrimaryButton";
import "./styles/Clients.css";

export default function Clients({ token, apiUrl, onTokenExpired }) {
    const {
        fetchClients,
        createClient: createClientAPI,
        updateClient: updateClientAPI,
        deleteClient: deleteClientAPI,
        invalidateCache,
    } = useData();
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [modalError, setModalError] = useState("");
    const [affiliateModalError, setAffiliateModalError] = useState("");
    const { config, getGenderHelpers } = useConfig();
    const g = getGenderHelpers("client");
    const filtersContainerRef = useRef(null);

    // State persistence
    const { values, updateValue } = useUrlState(
        { filter: "all", search: "" },
        { debounce: true, debounceTime: 300 },
    );
    const filter = values.filter;
    const searchTerm = values.search;
    const setFilter = (val) => updateValue("filter", val);
    const setSearchTerm = (val) => updateValue("search", val);

    const [selectedClient, setSelectedClient] = useState(null);
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [showAffiliatesPanel, setShowAffiliatesPanel] = useState(false);
    const [showAffiliateModal, setShowAffiliateModal] = useState(false);
    const [affiliateModalMode, setAffiliateModalMode] = useState("create");
    const [affiliates, setAffiliates] = useState([]);
    const [selectedAffiliate, setSelectedAffiliate] = useState(null);
    const [formData, setFormData] = useState(getInitialFormData());
    const [affiliateForm, setAffiliateForm] = useState(
        getInitialAffiliateForm(),
    );

    useEffect(() => {
        loadClients();
    }, []);

    // Equalize filter button widths
    useEffect(() => {
        if (filtersContainerRef.current) {
            const buttons = filtersContainerRef.current.querySelectorAll(
                ".clients-filter-button",
            );
            if (buttons.length > 0) {
                // Reset min-width to measure natural width
                buttons.forEach((btn) => (btn.style.minWidth = "auto"));

                // Calculate minimum button width
                let minButtonWidth = 0;
                buttons.forEach((btn) => {
                    const width = btn.offsetWidth;
                    if (width > minButtonWidth) {
                        minButtonWidth = width;
                    }
                });

                // Ensure minimum width of 120px
                minButtonWidth = Math.max(minButtonWidth, 120);

                // Apply minimum width to all buttons
                buttons.forEach((btn) => {
                    btn.style.minWidth = minButtonWidth + "px";
                });
            }
        }
    }, [filter, clients]); // Re-calculate when filter or clients change

    const loadClients = async (forceRefresh = false) => {
        setLoading(true);
        setError("");
        try {
            const response = await fetchClients(
                { include_stats: true },
                forceRefresh,
            );
            setClients(response.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const loadAffiliates = async (clientId) => {
        try {
            const data = await clientsApi.loadAffiliates(
                apiUrl,
                token,
                clientId,
                onTokenExpired,
            );
            setAffiliates(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const createClient = async () => {
        setModalError("");
        try {
            await createClientAPI(formData);
            invalidateCache("clients");
            await loadClients(true);
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const updateClient = async () => {
        setModalError("");
        try {
            await updateClientAPI(selectedClient.id, formData);
            invalidateCache("clients");
            await loadClients(true);
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const archiveClient = async (clientId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este cliente?"))
            return;

        try {
            await deleteClientAPI(clientId);
            invalidateCache("clients");
            await loadClients(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveClient = async (clientId) => {
        try {
            // Note: We still need to use the API directly for unarchive
            // as DataContext doesn't have an unarchive method
            await clientsApi.unarchiveClient(
                apiUrl,
                token,
                clientId,
                onTokenExpired,
            );
            invalidateCache("clients");
            await loadClients(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const createAffiliate = async () => {
        setAffiliateModalError("");
        try {
            await clientsApi.createAffiliate(
                apiUrl,
                token,
                selectedClient.id,
                affiliateForm,
                onTokenExpired,
            );
            await loadAffiliates(selectedClient.id);
            closeAffiliateModal();
        } catch (err) {
            setAffiliateModalError(err.message);
        }
    };

    const updateAffiliate = async () => {
        setAffiliateModalError("");
        try {
            await clientsApi.updateAffiliate(
                apiUrl,
                token,
                selectedAffiliate.id,
                affiliateForm,
                onTokenExpired,
            );
            await loadAffiliates(selectedClient.id);
            closeAffiliateModal();
        } catch (err) {
            setAffiliateModalError(err.message);
        }
    };

    const deleteAffiliate = async (affiliateId) => {
        if (!window.confirm("Tem certeza que deseja deletar este afiliado?"))
            return;

        try {
            await clientsApi.deleteAffiliate(
                apiUrl,
                token,
                affiliateId,
                onTokenExpired,
            );
            await loadAffiliates(selectedClient.id);
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

    const openAffiliatesPanel = async (client) => {
        setSelectedClient(client);
        await loadAffiliates(client.id);
        setShowAffiliatesPanel(true);
    };

    const closeAffiliatesPanel = () => {
        setShowAffiliatesPanel(false);
        setSelectedClient(null);
        setAffiliates([]);
    };

    const openCreateAffiliateModal = () => {
        setAffiliateModalMode("create");
        setSelectedAffiliate(null);
        setAffiliateForm(getInitialAffiliateForm());
        setShowAffiliateModal(true);
    };

    const openEditAffiliateModal = (affiliate) => {
        setAffiliateModalMode("edit");
        setSelectedAffiliate(affiliate);
        setAffiliateForm(formatAffiliateForEdit(affiliate));
        setShowAffiliateModal(true);
    };

    const closeAffiliateModal = () => {
        setShowAffiliateModal(false);
        setSelectedAffiliate(null);
        setAffiliateForm(getInitialAffiliateForm());
        setAffiliateModalError("");
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

    const handleAffiliateSubmit = (e) => {
        e.preventDefault();
        if (affiliateModalMode === "create") {
            createAffiliate();
        } else {
            updateAffiliate();
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
                    Carregando {config.labels.clients.toLowerCase()}...
                </div>
            </div>
        );
    }

    return (
        <div className="clients-container">
            <div className="clients-header">
                <h1 className="clients-title">
                    👥 {config.labels.clients || "Clientes"}
                </h1>
                <div className="button-group">
                    <PrimaryButton onClick={openCreateModal}>
                        + {g.new} {config.labels.client}
                    </PrimaryButton>
                </div>
            </div>

            {error && !showModal && (
                <div className="clients-error">{error}</div>
            )}

            <div className="clients-filters" ref={filtersContainerRef}>
                <button
                    onClick={() => setFilter("all")}
                    className={`clients-filter-button ${filter === "all" ? "active-all" : ""}`}
                >
                    {g.all} ({clients.length})
                </button>
                <button
                    onClick={() => setFilter("active")}
                    className={`clients-filter-button ${filter === "active" ? "active-active" : ""}`}
                >
                    {g.active}
                </button>
                <button
                    onClick={() => setFilter("inactive")}
                    className={`clients-filter-button ${filter === "inactive" ? "active-inactive" : ""}`}
                >
                    {g.inactive}
                </button>
                <button
                    onClick={() => setFilter("archived")}
                    className={`clients-filter-button ${filter === "archived" ? "active-archived" : ""}`}
                >
                    {g.archived}
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
                    openAffiliatesPanel={openAffiliatesPanel}
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

            {showAffiliatesPanel && (
                <AffiliatesPanel
                    selectedClient={selectedClient}
                    affiliates={affiliates}
                    onCreateAffiliate={openCreateAffiliateModal}
                    onEditAffiliate={openEditAffiliateModal}
                    onDeleteAffiliate={deleteAffiliate}
                    onClose={closeAffiliatesPanel}
                />
            )}

            <AffiliateModal
                showModal={showAffiliateModal}
                modalMode={affiliateModalMode}
                affiliateForm={affiliateForm}
                setAffiliateForm={setAffiliateForm}
                onSubmit={handleAffiliateSubmit}
                onClose={closeAffiliateModal}
                error={affiliateModalError}
            />
        </div>
    );
}
