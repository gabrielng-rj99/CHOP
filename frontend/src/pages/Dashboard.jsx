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
        } else if (daysUntilExpiration <= 30) {
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

    // Clientes que fazem aniversário no mês atual
    const birthdayClients = clients.filter((c) => {
        if (c.archived_at || c.status !== "ativo" || !c.birth_date) {
            return false;
        }

        const birthDate = new Date(c.birth_date);
        const currentMonth = new Date().getMonth();
        const birthMonth = birthDate.getMonth();

        return birthMonth === currentMonth;
    });

    const archivedClients = clients.filter((c) => c.archived_at);

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
                    <div className="dashboard-stat-label">Clientes Ativos</div>
                    <div className="dashboard-stat-value clients">
                        {activeClients.length}
                    </div>
                </div>

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
                    <div className="dashboard-stat-label">
                        Clientes Arquivados
                    </div>
                    <div className="dashboard-stat-value archived">
                        {archivedClients.length}
                    </div>
                </div>

                <div className="dashboard-stat-card">
                    <div className="dashboard-stat-label">Não Iniciados</div>
                    <div className="dashboard-stat-value not-started">
                        {notStartedContracts.length}
                    </div>
                </div>
            </div>

            <div className="dashboard-content-grid">
                <div className="dashboard-section-card">
                    <h2 className="dashboard-section-title">
                        Aniversariantes do Mês ({birthdayClients.length})
                    </h2>
                    {birthdayClients.length === 0 ? (
                        <p className="dashboard-section-empty">
                            Nenhum aniversariante este mês
                        </p>
                    ) : (
                        <div className="dashboard-contracts-list">
                            {birthdayClients.slice(0, 5).map((client) => {
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
                                            {new Date(
                                                client.birth_date,
                                            ).toLocaleDateString("pt-BR", {
                                                day: "2-digit",
                                                month: "2-digit",
                                            })}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

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
                                            {contract.model || "Sem modelo"}
                                        </div>
                                        <div className="dashboard-contract-key">
                                            {contract.product_key ||
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
                                            {contract.model || "Sem modelo"}
                                        </div>
                                        <div className="dashboard-contract-key">
                                            {contract.product_key ||
                                                "Sem chave"}
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
