import React, { useState, useEffect } from "react";
import "./Dashboard.css";

export default function Dashboard({ token, apiUrl }) {
    const [contracts, setContracts] = useState([]);
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        setLoading(true);
        setError("");

        try {
            const headers = {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            };

            const [contractsRes, clientsRes] = await Promise.all([
                fetch(`${apiUrl}/api/contracts`, { headers }),
                fetch(`${apiUrl}/api/clients`, { headers }),
            ]);

            if (!contractsRes.ok || !clientsRes.ok) {
                throw new Error("Erro ao carregar dados");
            }

            const contractsData = await contractsRes.json();
            const clientsData = await clientsRes.json();

            setContracts(contractsData.data || []);
            setClients(clientsData.data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
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
            <h1 className="dashboard-title">Dashboard</h1>

            <div className="dashboard-stats-grid">
                <div className="dashboard-stat-card">
                    <div className="dashboard-stat-label">Contratos Ativos</div>
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
                        Contratos Expirados
                    </div>
                    <div className="dashboard-stat-value expired">
                        {expiredContracts.length}
                    </div>
                </div>

                <div className="dashboard-stat-card">
                    <div className="dashboard-stat-label">Clientes Ativos</div>
                    <div className="dashboard-stat-value clients">
                        {activeClients.length}
                    </div>
                </div>
            </div>

            <div className="dashboard-content-grid">
                <div className="dashboard-section-card">
                    <h2 className="dashboard-section-title">
                        Contratos Expirando em Breve
                    </h2>
                    {expiringContracts.length === 0 ? (
                        <p className="dashboard-section-empty">
                            Nenhum contrato expirando
                        </p>
                    ) : (
                        <div className="dashboard-contracts-list">
                            {expiringContracts.slice(0, 5).map((contract) => {
                                const endDate = new Date(contract.end_date);
                                const now = new Date();
                                const daysLeft = Math.ceil(
                                    (endDate - now) / (1000 * 60 * 60 * 24),
                                );

                                return (
                                    <div
                                        key={contract.id}
                                        className="dashboard-contract-item expiring"
                                    >
                                        <div className="dashboard-contract-model">
                                            {contract.model}
                                        </div>
                                        <div className="dashboard-contract-key">
                                            {contract.product_key}
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
                        Contratos Expirados
                    </h2>
                    {expiredContracts.length === 0 ? (
                        <p className="dashboard-section-empty">
                            Nenhum contrato expirado
                        </p>
                    ) : (
                        <div className="dashboard-contracts-list">
                            {expiredContracts.slice(0, 5).map((contract) => {
                                const endDate = new Date(contract.end_date);
                                const now = new Date();
                                const daysExpired = Math.ceil(
                                    (now - endDate) / (1000 * 60 * 60 * 24),
                                );

                                return (
                                    <div
                                        key={contract.id}
                                        className="dashboard-contract-item expired"
                                    >
                                        <div className="dashboard-contract-model">
                                            {contract.model}
                                        </div>
                                        <div className="dashboard-contract-key">
                                            {contract.product_key}
                                        </div>
                                        <div className="dashboard-contract-days expired">
                                            Expirado há {daysExpired} dias
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
