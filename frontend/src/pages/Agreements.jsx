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
import { agreementsApi } from "../api/agreementsApi";
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
import AgreementModal from "../components/agreements/AgreementModal";
import "./Agreements.css";

export default function Contracts({ token, apiUrl, onTokenExpired }) {
    const [contracts, setAgreements] = useState([]);
    const [clients, setEntities] = useState([]);
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
                loadAgreements(),
                loadEntities(),
                loadCategories(),
            ]);
        } finally {
            setLoading(false);
        }
    };

    const loadAgreements = async () => {
        setError("");
        try {
            const data = await agreementsApi.loadAgreements(apiUrl, token, onTokenExpired);
            setAgreements(data);
        } catch (err) {
            setError(err.message);
        }
    };

    const loadEntities = async () => {
        try {
            const data = await agreementsApi.loadEntities(apiUrl, token, onTokenExpired);
            setEntities(data);
        } catch (err) {
            console.error("Erro ao carregar clientes:", err);
        }
    };

    const loadCategories = async () => {
        try {
            const data = await agreementsApi.loadCategories(apiUrl, token, onTokenExpired);
            setCategories(data);
        } catch (err) {
            console.error("Erro ao carregar categorias:", err);
        }
    };

    const loadSubcategories = async (categoryId) => {
        try {
            const data = await agreementsApi.loadSubcategories(
                apiUrl,
                token,
                categoryId,
                onTokenExpired,
            );
            setLines(data);
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
            await agreementsApi.createAgreement(apiUrl, token, apiData, onTokenExpired);
            await loadAgreements();
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
            await loadAgreements();
            closeModal();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleArchiveContract = async (contractId) => {
        if (!window.confirm("Tem certeza que deseja arquivar este contrato?"))
            return;

        try {
            await agreementsApi.archiveAgreement(apiUrl, token, contractId, onTokenExpired);
            await loadAgreements();
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUnarchiveAgreement = async (contractId) => {
        try {
            await agreementsApi.unarchiveAgreement(apiUrl, token, contractId, onTokenExpired);
            await loadAgreements();
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
            <div className="contracts-loading">
                <div className="contracts-loading-text">
                    Carregando contratos...
                </div>
            </div>
        );
    }

    return (
        <div className="contracts-container">
            <div className="contracts-header">
                <h1 className="contracts-title">Contratos</h1>
                <div className="contracts-button-group">
                    <button
                        onClick={loadAgreements}
                        className="contracts-button-secondary"
                    >
                        Atualizar
                    </button>
                    <button
                        onClick={openCreateModal}
                        className="contracts-button"
                    >
                        + Novo Contrato
                    </button>
                </div>
            </div>

            {error && <div className="contracts-error">{error}</div>}

            <div className="contracts-filters">
                <button
                    onClick={() => setFilter("all")}
                    className={`contracts-filter-button ${filter === "all" ? "active-all" : ""}`}
                >
                    Todos ({contracts.filter((c) => !c.archived_at).length})
                </button>
                <button
                    onClick={() => setFilter("active")}
                    className={`contracts-filter-button ${filter === "active" ? "active-active" : ""}`}
                >
                    Ativos
                </button>
                <button
                    onClick={() => setFilter("not-started")}
                    className={`contracts-filter-button ${filter === "not-started" ? "active-not-started" : ""}`}
                >
                    Não Iniciados
                </button>
                <button
                    onClick={() => setFilter("expiring")}
                    className={`contracts-filter-button ${filter === "expiring" ? "active-expiring" : ""}`}
                >
                    Expirando
                </button>
                <button
                    onClick={() => setFilter("expired")}
                    className={`contracts-filter-button ${filter === "expired" ? "active-expired" : ""}`}
                >
                    Expirados
                </button>
                <button
                    onClick={() => setFilter("archived")}
                    className={`contracts-filter-button ${filter === "archived" ? "active-archived" : ""}`}
                >
                    Arquivados
                </button>

                <input
                    type="text"
                    placeholder="Buscar por modelo, chave, cliente..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="contracts-search-input"
                />
            </div>

            <div className="contracts-table-wrapper">
                {/* <div className="contracts-table-header">
                    <h2 className="contracts-table-header-title">Contratos</h2>
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
                                label="Modelo"
                                value={selectedContract.model || "-"}
                            />
                            <DetailRow
                                label="Chave do Produto"
                                value={selectedContract.item_key || "-"}
                            />
                            <DetailRow
                                label="Cliente"
                                value={getClientName(
                                    selectedContract.entity_id,
                                    clients,
                                )}
                            />
                            {selectedContract.dependent && (
                                <DetailRow
                                    label="Dependente"
                                    value={selectedContract.dependent.name}
                                />
                            )}
                            <DetailRow
                                label="Categoria"
                                value={getCategoryName(
                                    selectedContract.subcategory_id,
                                    categories,
                                )}
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
