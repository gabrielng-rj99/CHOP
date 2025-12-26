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
import { useConfig } from "../contexts/ConfigContext";
import { useData } from "../contexts/DataContext";
import RefreshButton from "../components/common/RefreshButton";
import "./styles/Dashboard.css";

export default function Dashboard({ token, apiUrl, onTokenExpired }) {
    const { config, getPersistentFilter, setPersistentFilter } = useConfig();
    const {
        fetchAgreements,
        fetchEntities,
        fetchCategories,
        fetchSubcategories,
    } = useData();
    const [contracts, setAgreements] = useState([]);
    const [clients, setEntities] = useState([]);
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [showBirthdays, setShowBirthdays] = useState(() =>
        getPersistentFilter("dashboard_show_birthdays", false),
    );
    // Initialize with null to indicate "not set yet", will be set based on data or persistence
    const [birthdayFilter, setBirthdayFilter] = useState(() =>
        getPersistentFilter("dashboard_birthday_filter", null),
    );

    // Dashboard settings from backend
    const [dashboardSettings, setDashboardSettings] = useState({
        show_birthdays: true,
        birthdays_days_ahead: 7,
        show_recent_activity: true,
        recent_activity_count: 10,
        show_statistics: true,
        show_expiring_agreements: true,
        expiring_days_ahead: 30,
        show_quick_actions: true,
    });

    // Save persistent states
    useEffect(() => {
        setPersistentFilter("dashboard_show_birthdays", showBirthdays);
    }, [showBirthdays, setPersistentFilter]);

    useEffect(() => {
        if (birthdayFilter) {
            setPersistentFilter("dashboard_birthday_filter", birthdayFilter);
        }
    }, [birthdayFilter, setPersistentFilter]);

    // Load dashboard settings from backend
    useEffect(() => {
        const loadDashboardSettings = async () => {
            try {
                const response = await fetch(
                    `${apiUrl}/system-config/dashboard`,
                    {
                        headers: {
                            Authorization: `Bearer ${token}`,
                        },
                    },
                );
                if (response.ok) {
                    const data = await response.json();
                    setDashboardSettings((prev) => ({ ...prev, ...data }));
                }
            } catch (err) {
                console.error("Error loading dashboard settings:", err);
            }
        };
        if (token && apiUrl) {
            loadDashboardSettings();
        }
    }, [token, apiUrl]);

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async (forceRefresh = false) => {
        setLoading(true);
        setError("");

        try {
            // Fetch data using cache
            const [contractsData, clientsData, categoriesData] =
                await Promise.all([
                    fetchAgreements({}, forceRefresh),
                    fetchEntities({}, forceRefresh),
                    fetchCategories(forceRefresh),
                ]);

            setAgreements(contractsData.data || []);
            setEntities(clientsData.data || []);
            setCategories(categoriesData.data || []);

            // Load all lines for all categories
            const allLinesPromises = (categoriesData.data || []).map(
                (category) =>
                    fetchSubcategories(category.id, forceRefresh)
                        .then((data) => data.data || [])
                        .catch(() => []),
            );
            const allLinesResults = await Promise.all(allLinesPromises);
            const flattenedLines = allLinesResults.flat();
            setLines(flattenedLines);

            // Smart filter logic: If birthdayFilter is null (not loaded from session), determine based on count
            if (!birthdayFilter) {
                const activeCount = (clientsData.data || []).filter(
                    (c) => !c.archived_at && c.status === "ativo",
                ).length;
                setBirthdayFilter(activeCount > 120 ? "day" : "month");
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const getContractStatus = (contract) => {
        // Se não tem data de término, é considerado ativo
        if (!contract.end_date || contract.end_date === "") {
            return { status: "Ativo", color: "#27ae60" };
        }

        const endDate = new Date(contract.end_date);
        const startDate = contract.start_date
            ? new Date(contract.start_date)
            : null;
        const now = new Date();

        // Se tem data de início no futuro, é "Não Iniciado"
        if (startDate && startDate > now) {
            return { status: "Não Iniciado", color: "#3498db" };
        }

        const daysUntilExpiration = Math.ceil(
            (endDate - now) / (1000 * 60 * 60 * 24),
        );

        if (daysUntilExpiration < 0) {
            return { status: "Expirado", color: "#e74c3c" };
        } else if (
            daysUntilExpiration <= dashboardSettings.expiring_days_ahead
        ) {
            return { status: "Expirando", color: "#f39c12" };
        } else {
            return { status: "Ativo", color: "#27ae60" };
        }
    };

    const notStartedContracts = contracts.filter((c) => {
        const status = getContractStatus(c);
        return !c.archived_at && status.status === "Não Iniciado";
    });

    const activeContracts = contracts.filter((c) => {
        const status = getContractStatus(c);
        return !c.archived_at && status.status === "Ativo";
    });

    const expiringContracts = contracts.filter((c) => {
        const status = getContractStatus(c);
        return !c.archived_at && status.status === "Expirando";
    });

    const expiredContracts = contracts.filter((c) => {
        const status = getContractStatus(c);
        return !c.archived_at && status.status === "Expirado";
    });

    const activeClients = clients.filter(
        (c) => !c.archived_at && c.status === "ativo",
    );

    const inactiveClients = clients.filter(
        (c) => !c.archived_at && c.status === "inativo",
    );

    const archivedClients = clients.filter((c) => c.archived_at);

    // Clientes que fazem aniversário no mês atual ou dia atual (respeitando days_ahead)
    const birthdayClients = clients.filter((c) => {
        if (c.archived_at || c.status !== "ativo" || !c.birth_date) {
            return false;
        }

        const birthDate = new Date(c.birth_date);
        const now = new Date();
        const currentMonth = now.getMonth();
        const currentDay = now.getDate();
        const birthMonth = birthDate.getMonth();
        const birthDay = birthDate.getDate();

        if (birthdayFilter === "day") {
            return birthMonth === currentMonth && birthDay === currentDay;
        } else if (birthdayFilter === "week") {
            // Check if birthday is within the next X days
            const daysAhead = dashboardSettings.birthdays_days_ahead || 7;
            const today = new Date();
            today.setHours(0, 0, 0, 0);

            for (let i = 0; i <= daysAhead; i++) {
                const checkDate = new Date(today);
                checkDate.setDate(checkDate.getDate() + i);
                if (
                    checkDate.getMonth() === birthMonth &&
                    checkDate.getDate() === birthDay
                ) {
                    return true;
                }
            }
            return false;
        } else {
            // Default to month if birthdayFilter is null or 'month'
            return birthMonth === currentMonth;
        }
    });

    const totalCategories = categories.length;
    const totalLines = lines.length;

    if (loading) {
        return (
            <div className="dashboard-loading">
                <div className="dashboard-loading-text">Carregando...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="dashboard-error-container">
                <div className="dashboard-error-message">{error}</div>
                <button onClick={loadData} className="dashboard-error-button">
                    Tentar Novamente
                </button>
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
                    marginBottom: "20px",
                }}
            >
                <h1 className="dashboard-title" style={{ margin: 0 }}>
                    📈 Dashboard
                </h1>
                <RefreshButton
                    onClick={() => loadData(true)}
                    disabled={loading}
                    isLoading={loading}
                    icon="↻"
                />
            </div>

            {/* Statistics Cards - controlled by show_statistics */}
            {dashboardSettings.show_statistics && (
                <div className="dashboard-stats-grid">
                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            Clientes Ativos
                        </div>
                        <div className="dashboard-stat-value clients">
                            {activeClients.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            {config.labels.agreements || "Contratos"} Ativos
                        </div>
                        <div className="dashboard-stat-value active">
                            {activeContracts.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            Expirando em Breve
                        </div>
                        <div className="dashboard-stat-value expiring">
                            {expiringContracts.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            {config.labels.agreements || "Contratos"} Expirados
                        </div>
                        <div className="dashboard-stat-value expired">
                            {expiredContracts.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            Clientes Inativos
                        </div>
                        <div className="dashboard-stat-value inactive">
                            {inactiveClients.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">
                            Clientes Arquivados
                        </div>
                        <div className="dashboard-stat-value archived">
                            {archivedClients.length}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">Categorias</div>
                        <div className="dashboard-stat-value categories">
                            {totalCategories}
                        </div>
                    </div>

                    <div className="dashboard-stat-card">
                        <div className="dashboard-stat-label">Linhas</div>
                        <div className="dashboard-stat-value lines">
                            {totalLines}
                        </div>
                    </div>
                </div>
            )}

            {/* Birthdays Section - controlled by show_birthdays */}
            {dashboardSettings.show_birthdays && (
                <>
                    <div style={{ marginTop: "20px", marginBottom: "10px" }}>
                        <a
                            href="#"
                            onClick={(e) => {
                                e.preventDefault();
                                setShowBirthdays(!showBirthdays);
                            }}
                            style={{
                                fontSize: "13px",
                                color: "#3498db",
                                textDecoration: "none",
                                cursor: "pointer",
                            }}
                        >
                            {showBirthdays ? "Ocultar" : "Exibir"}{" "}
                            aniversariantes
                        </a>
                    </div>

                    {showBirthdays && (
                        <div className="dashboard-content-grid">
                            <div className="dashboard-section-card">
                                <div
                                    style={{
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                        marginBottom: "15px",
                                    }}
                                >
                                    <h2
                                        className="dashboard-section-title"
                                        style={{ margin: 0 }}
                                    >
                                        Aniversariantes{" "}
                                        {birthdayFilter === "day"
                                            ? "do Dia"
                                            : birthdayFilter === "week"
                                              ? `(próximos ${dashboardSettings.birthdays_days_ahead} dias)`
                                              : "do Mês"}{" "}
                                        ({birthdayClients.length})
                                    </h2>
                                    <div
                                        style={{ display: "flex", gap: "10px" }}
                                    >
                                        <button
                                            onClick={() =>
                                                setBirthdayFilter("day")
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                fontSize: "12px",
                                                border: "1px solid #3498db",
                                                background:
                                                    birthdayFilter === "day"
                                                        ? "#3498db"
                                                        : "white",
                                                color:
                                                    birthdayFilter === "day"
                                                        ? "white"
                                                        : "#3498db",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                            }}
                                        >
                                            Do Dia
                                        </button>
                                        <button
                                            onClick={() =>
                                                setBirthdayFilter("week")
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                fontSize: "12px",
                                                border: "1px solid #3498db",
                                                background:
                                                    birthdayFilter === "week"
                                                        ? "#3498db"
                                                        : "white",
                                                color:
                                                    birthdayFilter === "week"
                                                        ? "white"
                                                        : "#3498db",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                            }}
                                        >
                                            Próximos{" "}
                                            {
                                                dashboardSettings.birthdays_days_ahead
                                            }{" "}
                                            dias
                                        </button>
                                        <button
                                            onClick={() =>
                                                setBirthdayFilter("month")
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                fontSize: "12px",
                                                border: "1px solid #3498db",
                                                background:
                                                    birthdayFilter === "month"
                                                        ? "#3498db"
                                                        : "white",
                                                color:
                                                    birthdayFilter === "month"
                                                        ? "white"
                                                        : "#3498db",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                            }}
                                        >
                                            Do Mês
                                        </button>
                                    </div>
                                </div>
                                {birthdayClients.length === 0 ? (
                                    <p className="dashboard-section-empty">
                                        Nenhum aniversariante{" "}
                                        {birthdayFilter === "day"
                                            ? "hoje"
                                            : birthdayFilter === "week"
                                              ? `nos próximos ${dashboardSettings.birthdays_days_ahead} dias`
                                              : "este mês"}
                                    </p>
                                ) : (
                                    <div className="dashboard-contracts-list">
                                        {birthdayClients
                                            .slice(0, 10)
                                            .map((client) => {
                                                return (
                                                    <div
                                                        key={client.id}
                                                        className="dashboard-contract-item clients"
                                                    >
                                                        <div className="dashboard-contract-model">
                                                            {client.name}
                                                        </div>
                                                        <div className="dashboard-contract-key">
                                                            {client.registration_id ||
                                                                "Sem registro"}
                                                        </div>
                                                        <div className="dashboard-contract-days clients">
                                                            {(() => {
                                                                const dateStr =
                                                                    client.birth_date;
                                                                if (
                                                                    dateStr &&
                                                                    dateStr.match(
                                                                        /^\d{4}-\d{2}-\d{2}/,
                                                                    )
                                                                ) {
                                                                    const [
                                                                        year,
                                                                        month,
                                                                        day,
                                                                    ] = dateStr
                                                                        .split(
                                                                            "T",
                                                                        )[0]
                                                                        .split(
                                                                            "-",
                                                                        );
                                                                    return `${day}/${month}`;
                                                                }
                                                                return new Date(
                                                                    dateStr,
                                                                ).toLocaleDateString(
                                                                    "pt-BR",
                                                                    {
                                                                        day: "2-digit",
                                                                        month: "2-digit",
                                                                    },
                                                                );
                                                            })()}
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* Expiring Agreements Section - controlled by show_expiring_agreements */}
            {dashboardSettings.show_expiring_agreements && (
                <div
                    className="dashboard-content-grid"
                    style={{ marginTop: "20px" }}
                >
                    <div className="dashboard-section-card">
                        <h2 className="dashboard-section-title">
                            {config.labels.agreements || "Contratos"} Expirando
                            em Breve (próximos{" "}
                            {dashboardSettings.expiring_days_ahead} dias)
                        </h2>
                        {expiringContracts.length === 0 ? (
                            <p className="dashboard-section-empty">
                                Nenhum contrato expirando
                            </p>
                        ) : (
                            <div className="dashboard-contracts-list">
                                {expiringContracts
                                    .slice(0, 5)
                                    .map((contract) => {
                                        const endDate = new Date(
                                            contract.end_date,
                                        );
                                        const now = new Date();
                                        const daysLeft = Math.ceil(
                                            (endDate - now) /
                                                (1000 * 60 * 60 * 24),
                                        );

                                        return (
                                            <div
                                                key={contract.id}
                                                className="dashboard-contract-item expiring"
                                            >
                                                <div className="dashboard-contract-model">
                                                    {contract.model ||
                                                        "Sem modelo"}
                                                </div>
                                                <div className="dashboard-contract-key">
                                                    {contract.item_key ||
                                                        "Sem chave"}
                                                </div>
                                                <div className="dashboard-contract-days expiring">
                                                    {daysLeft} dias restantes
                                                </div>
                                            </div>
                                        );
                                    })}
                            </div>
                        )}
                    </div>

                    <div className="dashboard-section-card">
                        <h2 className="dashboard-section-title">
                            {config.labels.agreements || "Contratos"} Expirados
                        </h2>
                        {expiredContracts.length === 0 ? (
                            <p className="dashboard-section-empty">
                                Nenhum contrato expirado
                            </p>
                        ) : (
                            <div className="dashboard-contracts-list">
                                {expiredContracts
                                    .slice(0, 5)
                                    .map((contract) => {
                                        const endDate = new Date(
                                            contract.end_date,
                                        );
                                        const now = new Date();
                                        const daysExpired = Math.ceil(
                                            (now - endDate) /
                                                (1000 * 60 * 60 * 24),
                                        );

                                        return (
                                            <div
                                                key={contract.id}
                                                className="dashboard-contract-item expired"
                                            >
                                                <div className="dashboard-contract-model">
                                                    {contract.model ||
                                                        "Sem modelo"}
                                                </div>
                                                <div className="dashboard-contract-key">
                                                    {contract.item_key ||
                                                        "Sem chave"}
                                                </div>
                                                <div className="dashboard-contract-days expired">
                                                    Expirado há {daysExpired}{" "}
                                                    dias
                                                </div>
                                            </div>
                                        );
                                    })}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
