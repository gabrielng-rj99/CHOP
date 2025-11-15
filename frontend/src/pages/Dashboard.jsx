import React, { useState, useEffect } from "react";
import "./Dashboard.css";

export default function Dashboard({ token, apiUrl }) {
    const [contracts, setContracts] = useState([]);
    const [clients, setClients] = useState([]);
    const [categories, setCategories] = useState([]);
    const [lines, setLines] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [showBirthdays, setShowBirthdays] = useState(false);
    const [birthdayFilter, setBirthdayFilter] = useState("month"); // 'month' or 'day'

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

            const [contractsRes, clientsRes, categoriesRes] = await Promise.all(
                [
                    fetch(`${apiUrl}/api/contracts`, { headers }),
                    fetch(`${apiUrl}/api/clients`, { headers }),
                    fetch(`${apiUrl}/api/categories`, { headers }),
                ],
            );

            if (!contractsRes.ok || !clientsRes.ok || !categoriesRes.ok) {
                throw new Error("Erro ao carregar dados");
            }

            const contractsData = await contractsRes.json();
            const clientsData = await clientsRes.json();
            const categoriesData = await categoriesRes.json();

            setContracts(contractsData.data || []);
            setClients(clientsData.data || []);
            setCategories(categoriesData.data || []);

            // Load all lines for all categories
            const allLinesPromises = (categoriesData.data || []).map(
                (category) =>
                    fetch(`${apiUrl}/api/categories/${category.id}/lines`, {
                        headers,
                    })
                        .then((res) => (res.ok ? res.json() : { data: [] }))
                        .then((data) => data.data || [])
                        .catch(() => []),
            );
            const allLinesResults = await Promise.all(allLinesPromises);
            const flattenedLines = allLinesResults.flat();
            setLines(flattenedLines);
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

    const inactiveClients = clients.filter(
        (c) => !c.archived_at && c.status === "inativo",
    );

    const archivedClients = clients.filter((c) => c.archived_at);

    // Clientes que fazem aniversário no mês atual ou dia atual
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
        } else {
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
                    {showBirthdays ? "Ocultar" : "Exibir"} aniversariantes
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
                                {birthdayFilter === "day" ? "do Dia" : "do Mês"}{" "}
                                ({birthdayClients.length})
                            </h2>
                            <div style={{ display: "flex", gap: "10px" }}>
                                <button
                                    onClick={() => setBirthdayFilter("day")}
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
                                    onClick={() => setBirthdayFilter("month")}
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
                                {birthdayFilter === "day" ? "hoje" : "este mês"}
                            </p>
                        ) : (
                            <div className="dashboard-contracts-list">
                                {birthdayClients.slice(0, 10).map((client) => {
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
                                                            .split("T")[0]
                                                            .split("-");
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

            <div
                className="dashboard-content-grid"
                style={{ marginTop: "20px" }}
            >
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
