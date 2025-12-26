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

import React, { useState, useEffect, useRef } from "react";
import { useConfig } from "../contexts/ConfigContext";
import { useData } from "../contexts/DataContext";
import { entitiesApi } from "../api/entitiesApi";
import { useUrlState } from "../hooks/useUrlState";
import {
    filterClients,
    formatClientForEdit,
    formatDependentForEdit,
    getInitialFormData,
    getInitialDependentForm,
} from "../utils/clientHelpers";
import EntityModal from "../components/entities/EntityModal";
import EntitiesTable from "../components/entities/EntitiesTable";
import SubEntitiesPanel from "../components/entities/SubEntitiesPanel";
import SubEntityModal from "../components/entities/SubEntityModal";
import RefreshButton from "../components/common/RefreshButton";
import PrimaryButton from "../components/common/PrimaryButton";
import "./styles/Entities.css";

export default function Clients({ token, apiUrl, onTokenExpired }) {
    const {
        fetchEntities,
        createEntity: createEntityAPI,
        updateEntity: updateEntityAPI,
        deleteEntity: deleteEntityAPI,
        invalidateCache,
    } = useData();
    const [clients, setEntities] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [modalError, setModalError] = useState("");
    const [dependentModalError, setSubEntityModalError] = useState("");
    const { config, getGenderHelpers } = useConfig();
    const g = getGenderHelpers("entity");
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
    const [showSubEntitiesPanel, setShowSubEntitiesPanel] = useState(false);
    const [showSubEntityModal, setShowSubEntityModal] = useState(false);
    const [dependentModalMode, setSubEntityModalMode] = useState("create");
    const [dependents, setDependents] = useState([]);
    const [selectedDependent, setSelectedDependent] = useState(null);
    const [formData, setFormData] = useState(getInitialFormData());
    const [dependentForm, setDependentForm] = useState(
        getInitialDependentForm(),
    );

    useEffect(() => {
        loadEntities();
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

                // Calculate max width
                let maxWidth = 0;
                buttons.forEach((btn) => {
                    const width = btn.offsetWidth;
                    if (width > maxWidth) {
                        maxWidth = width;
                    }
                });

                // Apply max width to all buttons
                buttons.forEach((btn) => {
                    btn.style.minWidth = maxWidth + "px";
                });
            }
        }
    }, [filter, clients]); // Re-calculate when filter or clients change

    const loadEntities = async (forceRefresh = false) => {
        setLoading(true);
        setError("");
        try {
            const response = await fetchEntities(
                { include_stats: true },
                forceRefresh,
            );
            setEntities(response.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const loadSubEntities = async (clientId) => {
        try {
            const data = await entitiesApi.loadSubEntities(
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

    const createEntity = async () => {
        setModalError("");
        try {
            await createEntityAPI(formData);
            invalidateCache("entities");
            await loadEntities(true);
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const updateEntity = async () => {
        setModalError("");
        try {
            await updateEntityAPI(selectedClient.id, formData);
            invalidateCache("entities");
            await loadEntities(true);
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const archiveEntity = async (clientId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este cliente?"))
            return;

        try {
            await deleteEntityAPI(clientId);
            invalidateCache("entities");
            await loadEntities(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveEntity = async (clientId) => {
        try {
            // Note: We still need to use the API directly for unarchive
            // as DataContext doesn't have an unarchive method
            await entitiesApi.unarchiveEntity(
                apiUrl,
                token,
                clientId,
                onTokenExpired,
            );
            invalidateCache("entities");
            await loadEntities(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const createSubEntity = async () => {
        setSubEntityModalError("");
        try {
            await entitiesApi.createSubEntity(
                apiUrl,
                token,
                selectedClient.id,
                dependentForm,
                onTokenExpired,
            );
            await loadSubEntities(selectedClient.id);
            closeSubEntityModal();
        } catch (err) {
            setSubEntityModalError(err.message);
        }
    };

    const updateSubEntity = async () => {
        setSubEntityModalError("");
        try {
            await entitiesApi.updateSubEntity(
                apiUrl,
                token,
                selectedDependent.id,
                dependentForm,
                onTokenExpired,
            );
            await loadSubEntities(selectedClient.id);
            closeSubEntityModal();
        } catch (err) {
            setSubEntityModalError(err.message);
        }
    };

    const deleteSubEntity = async (dependentId) => {
        if (!window.confirm("Tem certeza que deseja deletar este dependente?"))
            return;

        try {
            await entitiesApi.deleteSubEntity(
                apiUrl,
                token,
                dependentId,
                onTokenExpired,
            );
            await loadSubEntities(selectedClient.id);
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

    const openSubEntitiesPanel = async (client) => {
        setSelectedClient(client);
        await loadSubEntities(client.id);
        setShowSubEntitiesPanel(true);
    };

    const closeSubEntitiesPanel = () => {
        setShowSubEntitiesPanel(false);
        setSelectedClient(null);
        setDependents([]);
    };

    const openCreateSubEntityModal = () => {
        setSubEntityModalMode("create");
        setSelectedDependent(null);
        setDependentForm(getInitialDependentForm());
        setShowSubEntityModal(true);
    };

    const openEditSubEntityModal = (dependent) => {
        setSubEntityModalMode("edit");
        setSelectedDependent(dependent);
        setDependentForm(formatDependentForEdit(dependent));
        setShowSubEntityModal(true);
    };

    const closeSubEntityModal = () => {
        setShowSubEntityModal(false);
        setSelectedDependent(null);
        setDependentForm(getInitialDependentForm());
        setSubEntityModalError("");
    };

    const closeModal = () => {
        setShowModal(false);
        setSelectedClient(null);
        setModalError("");
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (modalMode === "create") {
            createEntity();
        } else {
            updateEntity();
        }
    };

    const handleDependentSubmit = (e) => {
        e.preventDefault();
        if (dependentModalMode === "create") {
            createSubEntity();
        } else {
            updateSubEntity();
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
                    Carregando {config.labels.entities.toLowerCase()}...
                </div>
            </div>
        );
    }

    return (
        <div className="clients-container">
            <div className="clients-header">
                <h1 className="clients-title">
                    {config.labels.entities || "Clientes"}
                </h1>
                <div className="button-group">
                    <RefreshButton
                        onClick={() => loadEntities(true)}
                        disabled={loading}
                        isLoading={loading}
                        icon="↻"
                    />
                    <PrimaryButton onClick={openCreateModal}>
                        + {g.new} {config.labels.entity}
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
                <EntitiesTable
                    filteredClients={filteredClients}
                    openEditModal={openEditModal}
                    openSubEntitiesPanel={openSubEntitiesPanel}
                    archiveEntity={archiveEntity}
                    unarchiveEntity={unarchiveEntity}
                />
            </div>

            <EntityModal
                showModal={showModal}
                modalMode={modalMode}
                formData={formData}
                setFormData={setFormData}
                handleSubmit={handleSubmit}
                closeModal={closeModal}
                error={modalError}
            />

            {showSubEntitiesPanel && (
                <SubEntitiesPanel
                    selectedClient={selectedClient}
                    dependents={dependents}
                    onCreateDependent={openCreateSubEntityModal}
                    onEditDependent={openEditSubEntityModal}
                    onDeleteDependent={deleteSubEntity}
                    onClose={closeSubEntitiesPanel}
                />
            )}

            <SubEntityModal
                showModal={showSubEntityModal}
                modalMode={dependentModalMode}
                dependentForm={dependentForm}
                setDependentForm={setDependentForm}
                onSubmit={handleDependentSubmit}
                onClose={closeSubEntityModal}
                error={dependentModalError}
            />
        </div>
    );
}
