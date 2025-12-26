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
import { agreementsApi } from "../api/agreementsApi";
import { useUrlState } from "../hooks/useUrlState";
import {
    getInitialFormData,
    formatContractForEdit,
    filterContracts,
    formatDate,
    getContractStatus,
    getClientName,
    getCategoryName,
    prepareContractDataForAPI,
} from "../utils/contractHelpers";
import AgreementsTable from "../components/agreements/AgreementsTable";
import AgreementModal from "../components/agreements/AgreementsModal";
import RefreshButton from "../components/common/RefreshButton";
import PrimaryButton from "../components/common/PrimaryButton";
import "./styles/Agreements.css";

export default function Contracts({ token, apiUrl, onTokenExpired }) {
    const {
        fetchAgreements,
        fetchEntities,
        fetchCategories,
        fetchSubcategories,
        createAgreement,
        updateAgreement,
        deleteAgreement,
        invalidateCache,
    } = useData();
    const [contracts, setAgreements] = useState([]);
    const [clients, setEntities] = useState([]);
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [dependents, setDependents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    // State persistence
    const { values, updateValue } = useUrlState(
        { filter: "all", search: "" },
        { debounce: true, debounceTime: 300 },
    );
    const filter = values.filter;
    const searchTerm = values.search;
    const setFilter = (val) => updateValue("filter", val);
    const setSearchTerm = (val) => updateValue("search", val);

    const [showModal, setShowModal] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [modalMode, setModalMode] = useState("create");
    const [selectedContract, setSelectedContract] = useState(null);
    const [formData, setFormData] = useState(getInitialFormData());
    const { config, getGenderHelpers } = useConfig();
    const g = getGenderHelpers("agreement");

    const filtersContainerRef = useRef(null);

    useEffect(() => {
        loadInitialData();
    }, []);

    // Equalize filter button widths
    useEffect(() => {
        if (filtersContainerRef.current) {
            const buttons = filtersContainerRef.current.querySelectorAll(
                ".agreements-filter-button",
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
    }, [filter, contracts]); // Re-calculate when filter or contracts change

    const loadInitialData = async (forceRefresh = false) => {
        setLoading(true);
        try {
            await Promise.all([
                loadAgreements(forceRefresh),
                loadEntities(forceRefresh),
                loadCategories(forceRefresh),
            ]);
        } finally {
            setLoading(false);
        }
    };

    const loadAgreements = async (forceRefresh = false) => {
        setError("");
        try {
            const response = await fetchAgreements({}, forceRefresh);
            setAgreements(response.data || []);
        } catch (err) {
            setError(err.message);
        }
    };

    const loadEntities = async (forceRefresh = false) => {
        try {
            const response = await fetchEntities({}, forceRefresh);
            setEntities(response.data || []);
        } catch (err) {
            console.error("Erro ao carregar clientes:", err);
        }
    };

    const loadCategories = async (forceRefresh = false) => {
        try {
            const response = await fetchCategories(forceRefresh);
            setCategories(response.data || []);
        } catch (err) {
            console.error("Erro ao carregar categorias:", err);
        }
    };

    const loadSubcategories = async (categoryId, forceRefresh = false) => {
        try {
            const response = await fetchSubcategories(categoryId, forceRefresh);
            setLines(response.data || []);
        } catch (err) {
            console.error("Erro ao carregar linhas:", err);
        }
    };

    const loadSubEntities = async (clientId) => {
        try {
            const data = await agreementsApi.loadSubEntities(
                apiUrl,
                token,
                clientId,
                onTokenExpired,
            );
            setDependents(data);
        } catch (err) {
            console.error("Erro ao carregar dependentes:", err);
        }
    };

    const handleCreateContract = async () => {
        try {
            const apiData = prepareContractDataForAPI(formData);
            await agreementsApi.createAgreement(
                apiUrl,
                token,
                apiData,
                onTokenExpired,
            );
            invalidateCache("agreements");
            await loadAgreements(true);
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdateContract = async () => {
        setError("");
        try {
            const apiData = await agreementsApi.updateAgreement(
                apiUrl,
                token,
                selectedContract.id,
                prepareContractDataForAPI(formData),
                onTokenExpired,
            );
            invalidateCache("agreements");
            await loadAgreements(true);
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleArchiveContract = async (contractId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este contrato?"))
            return;

        try {
            await agreementsApi.archiveAgreement(
                apiUrl,
                token,
                contractId,
                onTokenExpired,
            );
            invalidateCache("agreements");
            await loadAgreements(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveAgreement = async (contractId) => {
        try {
            await agreementsApi.unarchiveAgreement(
                apiUrl,
                token,
                contractId,
                onTokenExpired,
            );
            invalidateCache("agreements");
            await loadAgreements(true);
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

        if (contract.entity_id) {
            loadSubEntities(contract.entity_id);
        }
        if (contract.line?.category_id) {
            loadSubcategories(contract.line.category_id);
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
            loadSubcategories(categoryId);
        } else {
            setLines([]);
        }
    };

    const handleClientChange = (clientId) => {
        if (clientId) {
            loadSubEntities(clientId);
        } else {
            setDependents([]);
        }
    };

    function compareContracts(a, b) {
        const now = new Date();
        const aEnd = new Date(a.end_date);
        const bEnd = new Date(b.end_date);

        // Contratos arquivados sempre por último
        if (a.archived_at && !b.archived_at) return 1;
        if (!a.archived_at && b.archived_at) return -1;
        if (a.archived_at && b.archived_at) return 0;

        const aDiff = aEnd - now;
        const bDiff = bEnd - now;

        // Quanto mais negativo, mais em cima
        return aDiff - bDiff;
    }

    const filteredContracts = filterContracts(
        [...contracts].sort(compareContracts),
        filter,
        searchTerm,
        clients,
        categories,
    );

    if (loading) {
        return (
            <div className="agreements-loading">
                <div className="agreements-loading-text">
                    Carregando acordos...
                </div>
            </div>
        );
    }

    return (
        <div className="agreements-container">
            <div className="agreements-header">
                <h1 className="agreements-title">
                    📄 {config.labels.agreements || "Acordos"}
                </h1>
                <div className="button-group">
                    <RefreshButton
                        onClick={() => loadInitialData(true)}
                        disabled={loading}
                        isLoading={loading}
                        icon="↻"
                    />
                    <PrimaryButton onClick={openCreateModal}>
                        + {g.new} {config.labels.agreement}
                    </PrimaryButton>
                </div>
            </div>

            {error && <div className="agreements-error">{error}</div>}

            <div className="agreements-filters" ref={filtersContainerRef}>
                <button
                    onClick={() => setFilter("all")}
                    className={`agreements-filter-button ${filter === "all" ? "active-all" : ""}`}
                >
                    {g.all} ({contracts.filter((c) => !c.archived_at).length})
                </button>
                <button
                    onClick={() => setFilter("active")}
                    className={`agreements-filter-button ${filter === "active" ? "active-active" : ""}`}
                >
                    {g.active}
                </button>
                <button
                    onClick={() => setFilter("not-started")}
                    className={`agreements-filter-button ${filter === "not-started" ? "active-not-started" : ""}`}
                >
                    Não Iniciados
                </button>
                <button
                    onClick={() => setFilter("expiring")}
                    className={`agreements-filter-button ${filter === "expiring" ? "active-expiring" : ""}`}
                >
                    Expirando
                </button>
                <button
                    onClick={() => setFilter("expired")}
                    className={`agreements-filter-button ${filter === "expired" ? "active-expired" : ""}`}
                >
                    Expirados
                </button>
                <button
                    onClick={() => setFilter("archived")}
                    className={`agreements-filter-button ${filter === "archived" ? "active-archived" : ""}`}
                >
                    {config.labels.archived || g.archived}
                </button>

                <input
                    type="text"
                    placeholder={`Buscar por modelo, chave, ${config.labels.entity.toLowerCase()}...`}
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="agreements-search-input"
                />
            </div>

            <div className="agreements-table-wrapper">
                {/* <div className="agreements-table-header">
                    <h2 className="agreements-table-header-title">Acordos</h2>
                </div>*/}
                <AgreementsTable
                    filteredContracts={filteredContracts}
                    clients={clients}
                    categories={categories}
                    onViewDetails={openDetailsModal}
                    onEdit={openEditModal}
                    onArchive={handleArchiveContract}
                    onUnarchive={handleUnarchiveAgreement}
                />
            </div>

            <AgreementModal
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
                error={error}
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
                                label={config.labels.model || "Modelo"}
                                value={selectedContract.model || "-"}
                            />
                            <DetailRow
                                label={
                                    config.labels.item_key || "Chave do Produto"
                                }
                                value={selectedContract.item_key || "-"}
                            />
                            <DetailRow
                                label={config.labels.entity || "Cliente"}
                                value={getClientName(
                                    selectedContract.entity_id,
                                    clients,
                                )}
                            />
                            {selectedContract.dependent && (
                                <DetailRow
                                    label={
                                        config.labels.dependent || "Dependente"
                                    }
                                    value={selectedContract.dependent.name}
                                />
                            )}
                            <DetailRow
                                label={config.labels.category || "Categoria"}
                                value={getCategoryName(
                                    selectedContract.subcategory_id,
                                    categories,
                                )}
                            />
                            <DetailRow
                                label={
                                    config.labels.subcategory || "Subcategoria"
                                }
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
