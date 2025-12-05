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

import React, { useState, useEffect } from "react";
import { entitiesApi } from "../api/entitiesApi";
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
import "./Entities.css";

export default function Clients({ token, apiUrl, onTokenExpired }) {
    const [clients, setEntities] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [modalError, setModalError] = useState("");
    const [dependentModalError, setSubEntityModalError] = useState("");
    const [filter, setFilter] = useState("active");
    const [searchTerm, setSearchTerm] = useState("");
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

    const loadEntities = async () => {
        setLoading(true);
        setError("");
        try {
            await entitiesApi.loadEntities(apiUrl, token, setEntities, setError, onTokenExpired);
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
            await entitiesApi.createEntity(apiUrl, token, formData, onTokenExpired);
            await loadEntities();
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const updateEntity = async () => {
        setModalError("");
        try {
            await entitiesApi.updateEntity(
                apiUrl,
                token,
                selectedClient.id,
                formData,
                onTokenExpired,
            );
            await loadEntities();
            closeModal();
        } catch (err) {
            setModalError(err.message);
        }
    };

    const archiveEntity = async (clientId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este cliente?"))
            return;

        try {
            await entitiesApi.archiveEntity(apiUrl, token, clientId, onTokenExpired);
            await loadEntities();
        } catch (err) {
            setError(err.message);
        }
    };

    const unarchiveEntity = async (clientId) => {
        try {
            await entitiesApi.unarchiveEntity(apiUrl, token, clientId, onTokenExpired);
            await loadEntities();
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
            await entitiesApi.deleteSubEntity(apiUrl, token, dependentId, onTokenExpired);
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
                        onClick={loadEntities}
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
