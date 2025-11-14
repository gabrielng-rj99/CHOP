import React, { useState, useEffect, useRef } from "react";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Contracts from "./pages/Contracts";
import Clients from "./pages/Clients";
import Categories from "./pages/Categories";
import Users from "./pages/Users";
import AuditLogs from "./pages/AuditLogs";
import "./App.css";

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
        <div className="app-container">
            <nav className="app-nav">
                <h2 className="app-nav-title">Contract Manager</h2>

                <button
                    onClick={() => navigate("dashboard")}
                    className={`app-nav-button ${currentPage === "dashboard" ? "active" : ""}`}
                >
                    Dashboard
                </button>

                <button
                    onClick={() => navigate("contracts")}
                    className={`app-nav-button ${currentPage === "contracts" ? "active" : ""}`}
                >
                    Contratos
                </button>

                <button
                    onClick={() => navigate("clients")}
                    className={`app-nav-button ${currentPage === "clients" ? "active" : ""}`}
                >
                    Clientes
                </button>

                <button
                    onClick={() => navigate("categories")}
                    className={`app-nav-button ${currentPage === "categories" ? "active" : ""}`}
                >
                    Categorias
                </button>

                {(user.role === "admin" || user.role === "full_admin") && (
                    <button
                        onClick={() => navigate("users")}
                        className={`app-nav-button ${currentPage === "users" ? "active" : ""}`}
                    >
                        Usuários
                    </button>
                )}

                {user.role === "full_admin" && (
                    <button
                        onClick={() => navigate("audit-logs")}
                        className={`app-nav-button ${currentPage === "audit-logs" ? "active" : ""}`}
                    >
                        Logs de Auditoria
                    </button>
                )}

                <div className="app-nav-footer">
                    <div className="app-nav-user-info">
                        <div className="app-nav-user-label">Usuário:</div>
                        <div className="app-nav-user-name">{user.username}</div>
                        <div className="app-nav-user-role">{user.role}</div>
                    </div>
                    <button onClick={logout} className="app-nav-logout-button">
                        Sair
                    </button>
                </div>
            </nav>

            <main className="app-main">
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
