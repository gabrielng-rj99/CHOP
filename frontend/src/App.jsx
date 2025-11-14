import React, { useState, useEffect, useRef } from "react";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Contracts from "./pages/Contracts";
import Clients from "./pages/Clients";
import Categories from "./pages/Categories";
import Users from "./pages/Users";
import AuditLogs from "./pages/AuditLogs";

const API_URL = "http://localhost:3000";

function App() {
    const [currentPage, setCurrentPage] = useState("login");
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [refreshToken, setRefreshToken] = useState(null);
    const refreshTimeoutRef = useRef(null);

    // Função para decodificar o JWT e pegar expiração
    function getTokenExpiration(token) {
        try {
            const payload = JSON.parse(atob(token.split(".")[1]));
            return payload.exp ? payload.exp * 1000 : null;
        } catch {
            return null;
        }
    }

    // Função para agendar renovação automática do token
    function scheduleTokenRefresh(token, refreshToken) {
        if (!token || !refreshToken) return;
        const exp = getTokenExpiration(token);
        if (!exp) return;
        const now = Date.now();
        // Renova 2 minutos antes de expirar
        const msUntilRefresh = Math.max(exp - now - 2 * 60 * 1000, 5000);
        if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current);
        refreshTimeoutRef.current = setTimeout(() => {
            renewAccessToken(refreshToken);
        }, msUntilRefresh);
    }

    // Função para renovar o access token usando o refresh token
    async function renewAccessToken(refreshToken) {
        try {
            const response = await fetch(`${API_URL}/api/refresh-token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });
            if (!response.ok) {
                throw new Error("Sessão expirada. Faça login novamente.");
            }
            const data = await response.json();
            setToken(data.data.token);
            scheduleTokenRefresh(data.data.token, refreshToken);
        } catch (err) {
            logout();
        }
    }

    const login = async (username, password) => {
        try {
            const response = await fetch(`${API_URL}/api/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || "Login falhou");
            }

            const data = await response.json();
            const userData = {
                id: data.data.user_id,
                username: data.data.username,
                role: data.data.role,
            };

            setToken(data.data.token);
            setRefreshToken(data.data.refresh_token);
            setUser(userData);
            setCurrentPage("dashboard");
            scheduleTokenRefresh(data.data.token, data.data.refresh_token);
        } catch (error) {
            throw error;
        }
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        setRefreshToken(null);
        setCurrentPage("login");
        if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current);
    };

    const navigate = (page) => {
        setCurrentPage(page);
    };

    useEffect(() => {
        if (token && refreshToken) {
            scheduleTokenRefresh(token, refreshToken);
        }
        return () => {
            if (refreshTimeoutRef.current)
                clearTimeout(refreshTimeoutRef.current);
        };
    }, [token, refreshToken]);

    if (!token || !user) {
        return <Login onLogin={login} />;
    }

    return (
        <div style={{ display: "flex", minHeight: "100vh" }}>
            <nav
                style={{
                    width: "250px",
                    background: "#2c3e50",
                    color: "white",
                    padding: "20px",
                    display: "flex",
                    flexDirection: "column",
                }}
            >
                <h2 style={{ marginBottom: "30px", fontSize: "20px" }}>
                    Contract Manager
                </h2>

                <button
                    onClick={() => navigate("dashboard")}
                    style={{
                        background:
                            currentPage === "dashboard"
                                ? "#34495e"
                                : "transparent",
                        color: "white",
                        border: "none",
                        padding: "12px 16px",
                        marginBottom: "8px",
                        cursor: "pointer",
                        textAlign: "left",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                >
                    Dashboard
                </button>

                <button
                    onClick={() => navigate("contracts")}
                    style={{
                        background:
                            currentPage === "contracts"
                                ? "#34495e"
                                : "transparent",
                        color: "white",
                        border: "none",
                        padding: "12px 16px",
                        marginBottom: "8px",
                        cursor: "pointer",
                        textAlign: "left",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                >
                    Contratos
                </button>

                <button
                    onClick={() => navigate("clients")}
                    style={{
                        background:
                            currentPage === "clients"
                                ? "#34495e"
                                : "transparent",
                        color: "white",
                        border: "none",
                        padding: "12px 16px",
                        marginBottom: "8px",
                        cursor: "pointer",
                        textAlign: "left",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                >
                    Clientes
                </button>

                <button
                    onClick={() => navigate("categories")}
                    style={{
                        background:
                            currentPage === "categories"
                                ? "#34495e"
                                : "transparent",
                        color: "white",
                        border: "none",
                        padding: "12px 16px",
                        marginBottom: "8px",
                        cursor: "pointer",
                        textAlign: "left",
                        borderRadius: "4px",
                        fontSize: "14px",
                    }}
                >
                    Categorias
                </button>

                {(user.role === "admin" || user.role === "full_admin") && (
                    <button
                        onClick={() => navigate("users")}
                        style={{
                            background:
                                currentPage === "users"
                                    ? "#34495e"
                                    : "transparent",
                            color: "white",
                            border: "none",
                            padding: "12px 16px",
                            marginBottom: "8px",
                            cursor: "pointer",
                            textAlign: "left",
                            borderRadius: "4px",
                            fontSize: "14px",
                        }}
                    >
                        Usuários
                    </button>
                )}

                {user.role === "full_admin" && (
                    <button
                        onClick={() => navigate("audit-logs")}
                        style={{
                            background:
                                currentPage === "audit-logs"
                                    ? "#34495e"
                                    : "transparent",
                            color: "white",
                            border: "none",
                            padding: "12px 16px",
                            marginBottom: "8px",
                            cursor: "pointer",
                            textAlign: "left",
                            borderRadius: "4px",
                            fontSize: "14px",
                        }}
                    >
                        Logs de Auditoria
                    </button>
                )}

                <div
                    style={{
                        marginTop: "auto",
                        paddingTop: "20px",
                        borderTop: "1px solid #34495e",
                    }}
                >
                    <div style={{ marginBottom: "16px", fontSize: "13px" }}>
                        <div style={{ opacity: 0.7 }}>Usuário:</div>
                        <div style={{ fontWeight: "bold" }}>
                            {user.username}
                        </div>
                        <div
                            style={{
                                opacity: 0.7,
                                textTransform: "capitalize",
                                fontSize: "12px",
                            }}
                        >
                            {user.role}
                        </div>
                    </div>
                    <button
                        onClick={logout}
                        style={{
                            width: "100%",
                            background: "#e74c3c",
                            color: "white",
                            border: "none",
                            padding: "10px",
                            cursor: "pointer",
                            borderRadius: "4px",
                            fontSize: "14px",
                        }}
                    >
                        Sair
                    </button>
                </div>
            </nav>

            <main style={{ flex: 1, padding: "20px" }}>
                {currentPage === "dashboard" && (
                    <Dashboard token={token} apiUrl={API_URL} />
                )}
                {currentPage === "contracts" && (
                    <Contracts token={token} apiUrl={API_URL} />
                )}
                {currentPage === "clients" && (
                    <Clients token={token} apiUrl={API_URL} />
                )}
                {currentPage === "categories" && (
                    <Categories token={token} apiUrl={API_URL} />
                )}
                {currentPage === "users" && (
                    <Users token={token} apiUrl={API_URL} user={user} />
                )}
                {currentPage === "audit-logs" && (
                    <AuditLogs token={token} apiUrl={API_URL} user={user} />
                )}
            </main>
        </div>
    );
}

export default App;
