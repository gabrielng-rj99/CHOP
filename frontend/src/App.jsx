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
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Contracts from "./pages/Agreements";
import Clients from "./pages/Entities";
import Categories from "./pages/Categories";
import Users from "./pages/Users";
import AuditLogs from "./pages/AuditLogs";

import Initialize from "./pages/Initialize";
import "./App.css";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faChartLine,
    faFileContract,
    faUserGroup,
    faTags,
    faUserGear,
    faSearchPlus,
    faRightFromBracket,
} from "@fortawesome/free-solid-svg-icons";

const API_URL = import.meta.env.VITE_API_URL || "/api";

function App() {
    const [appReady, setAppReady] = useState(false);
    const [isInitializing, setIsInitializing] = useState(true);
    const [currentPage, setCurrentPage] = useState("login");
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [refreshToken, setRefreshToken] = useState(null);
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
    const refreshTimeoutRef = useRef(null);

    // Check if app is initialized
    useEffect(() => {
        const checkInitialization = async () => {
            try {
                const response = await fetch(`${API_URL}/initialize/status`);
                if (response.ok) {
                    const data = await response.json();
                    if (data.is_initialized) {
                        setAppReady(true);
                        setIsInitializing(false);
                    }
                }
            } catch (error) {
                // App not ready, show initialize screen
                setIsInitializing(true);
            }
        };

        checkInitialization();
    }, []);

    // Load saved session on mount
    useEffect(() => {
        try {
            const savedToken = localStorage.getItem("token");
            const savedRefreshToken = localStorage.getItem("refreshToken");
            const savedUser = localStorage.getItem("user");
            const savedPage = localStorage.getItem("currentPage");

            if (savedToken && savedRefreshToken && savedUser) {
                setToken(savedToken);
                setRefreshToken(savedRefreshToken);
                setUser(JSON.parse(savedUser));
                setCurrentPage(savedPage || "dashboard");
            }
        } catch (error) {
            console.error("Error loading session:", error);
            localStorage.clear();
        }
    }, []);

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

        // Se o token já expirou ou está muito próximo de expirar (menos de 30 segundos), não agende
        if (exp - now < 30000) {
            console.log(
                "Token já expirado ou prestes a expirar, não agendando refresh",
            );
            return;
        }

        // Renova 2 minutos antes de expirar
        const msUntilRefresh = Math.max(exp - now - 2 * 60 * 1000, 60000); // mínimo 1 minuto

        // Só agende se não houver refresh já agendado ou se o novo tempo for significativamente diferente
        if (refreshTimeoutRef.current) {
            clearTimeout(refreshTimeoutRef.current);
        }

        console.log(
            `Token refresh agendado para daqui ${Math.round(msUntilRefresh / 1000)}s`,
        );
        refreshTimeoutRef.current = setTimeout(() => {
            renewAccessToken(refreshToken);
        }, msUntilRefresh);
    }

    // Função para renovar o access token usando o refresh token
    async function renewAccessToken(refreshToken) {
        try {
            console.log("Renovando access token...");
            const response = await fetch(`${API_URL}/refresh-token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });
            if (!response.ok) {
                throw new Error("Sessão expirada. Faça login novamente.");
            }
            const data = await response.json();
            const newToken = data.data.token;

            // Verificar se o novo token é realmente diferente e válido antes de atualizar
            if (newToken && newToken !== token) {
                setToken(newToken);
                try {
                    localStorage.setItem("token", newToken);
                    console.log("Token renovado com sucesso");
                } catch (e) {
                    console.error("Error saving token:", e);
                }
                // Não precisa chamar scheduleTokenRefresh aqui, o useEffect vai fazer isso
            } else {
                console.log("Token recebido é igual ao atual, não atualizando");
            }
        } catch (err) {
            console.error("Error refreshing token:", err);
            logout();
        }
    }

    const login = async (username, password) => {
        try {
            const response = await fetch(`${API_URL}/login`, {
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

            // Save to localStorage
            try {
                localStorage.setItem("token", data.data.token);
                localStorage.setItem("refreshToken", data.data.refresh_token);
                localStorage.setItem("user", JSON.stringify(userData));
                localStorage.setItem("currentPage", "dashboard");
            } catch (e) {
                console.error("Error saving to localStorage:", e);
            }

            scheduleTokenRefresh(data.data.token, data.data.refresh_token);
        } catch (error) {
            // Melhor tratamento de erros de rede
            if (
                error.message === "Failed to fetch" ||
                error.name === "TypeError"
            ) {
                throw new Error(
                    `Não foi possível conectar ao servidor. Verifique se o backend está rodando em ${API_URL}`,
                );
            }
            throw error;
        }
    };

    const logout = (errorMessage = null) => {
        setToken(null);
        setUser(null);
        setRefreshToken(null);
        setCurrentPage("login");

        // Se for erro de token expirado, redirecionar com parâmetro
        if (errorMessage && errorMessage.includes("Token inválido")) {
            window.history.replaceState(
                {},
                document.title,
                "/?session_expired=true",
            );
        }

        // Clear localStorage
        try {
            localStorage.removeItem("token");
            localStorage.removeItem("refreshToken");
            localStorage.removeItem("user");
            localStorage.removeItem("currentPage");
        } catch (e) {
            console.error("Error clearing localStorage:", e);
        }

        if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current);
    };

    const navigate = (page) => {
        setCurrentPage(page);
        try {
            localStorage.setItem("currentPage", page);
        } catch (e) {
            console.error("Error saving page:", e);
        }
    };

    const toggleSidebar = () => {
        setSidebarCollapsed(!sidebarCollapsed);
    };

    useEffect(() => {
        if (token && refreshToken) {
            // Verificar se o token ainda é válido antes de agendar refresh
            const exp = getTokenExpiration(token);
            const now = Date.now();

            // Só agendar se o token ainda tiver mais de 1 minuto de validade
            if (exp && exp - now > 60000) {
                scheduleTokenRefresh(token, refreshToken);
            } else if (exp && exp - now <= 60000 && exp - now > 0) {
                // Token está prestes a expirar, renovar imediatamente
                console.log("Token prestes a expirar, renovando imediatamente");
                renewAccessToken(refreshToken);
            }
        }
        return () => {
            if (refreshTimeoutRef.current)
                clearTimeout(refreshTimeoutRef.current);
        };
    }, [token, refreshToken]);

    // Show initialization screen if app is not ready
    if (isInitializing) {
        return (
            <Initialize
                onInitializationComplete={() => {
                    setIsInitializing(false);
                    setAppReady(true);
                }}
            />
        );
    }

    if (!token || !user) {
        return <Login onLogin={login} />;
    }

    return (
        <div className="app-container">
            <nav className={`app-nav ${sidebarCollapsed ? "collapsed" : ""}`}>
                <div className="app-nav-header">
                    <h2
                        className={`app-nav-title${sidebarCollapsed ? " hidden-title" : ""}`}
                    >
                        {sidebarCollapsed ? "CM" : "Entity Hub"}
                    </h2>
                    <button onClick={toggleSidebar} className="app-nav-toggle">
                        {sidebarCollapsed ? "☰" : "←"}
                    </button>
                </div>

                <div className="app-nav-items">
                    <button
                        onClick={() => navigate("dashboard")}
                        className={`app-nav-button ${currentPage === "dashboard" ? "active" : ""}`}
                        title="Dashboard"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faChartLine} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Dashboard</span>
                        )}
                    </button>

                    <button
                        onClick={() => navigate("contracts")}
                        className={`app-nav-button ${currentPage === "contracts" ? "active" : ""}`}
                        title="Contratos"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faFileContract} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Contratos</span>
                        )}
                    </button>

                    <button
                        onClick={() => navigate("clients")}
                        className={`app-nav-button ${currentPage === "clients" ? "active" : ""}`}
                        title="Clientes"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faUserGroup} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Clientes</span>
                        )}
                    </button>

                    <button
                        onClick={() => navigate("categories")}
                        className={`app-nav-button ${currentPage === "categories" ? "active" : ""}`}
                        title="Categorias"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faTags} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Categorias</span>
                        )}
                    </button>

                    {(user.role === "admin" || user.role === "root") && (
                        <button
                            onClick={() => navigate("users")}
                            className={`app-nav-button ${currentPage === "users" ? "active" : ""}`}
                            title="Usuários"
                        >
                            <span className="app-nav-icon">
                                <FontAwesomeIcon icon={faUserGear} />
                            </span>
                            {!sidebarCollapsed && (
                                <span className="app-nav-text">Usuários</span>
                            )}
                        </button>
                    )}

                    {user.role === "root" && (
                        <button
                            onClick={() => navigate("audit-logs")}
                            className={`app-nav-button ${currentPage === "audit-logs" ? "active" : ""}`}
                            title="Logs"
                        >
                            <span className="app-nav-icon">
                                <FontAwesomeIcon icon={faSearchPlus} />
                            </span>
                            {!sidebarCollapsed && (
                                <span className="app-nav-text">Logs</span>
                            )}
                        </button>
                    )}
                </div>

                <div className="app-nav-footer">
                    {!sidebarCollapsed && (
                        <div className="app-nav-user-info">
                            <div className="app-nav-user-label">Usuário:</div>
                            <div className="app-nav-user-name">
                                {user.username}
                            </div>
                            <div className="app-nav-user-role">{user.role}</div>
                        </div>
                    )}
                    <button
                        onClick={logout}
                        className="app-nav-logout-button"
                        title="Sair"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faRightFromBracket} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Sair</span>
                        )}
                    </button>
                </div>
            </nav>

            <main className="app-main">
                {currentPage === "dashboard" && (
                    <Dashboard
                        token={token}
                        apiUrl={API_URL}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
                {currentPage === "contracts" && (
                    <Contracts
                        token={token}
                        apiUrl={API_URL}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
                {currentPage === "clients" && (
                    <Clients
                        token={token}
                        apiUrl={API_URL}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
                {currentPage === "categories" && (
                    <Categories
                        token={token}
                        apiUrl={API_URL}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
                {currentPage === "users" && (
                    <Users
                        token={token}
                        apiUrl={API_URL}
                        user={user}
                        onLogout={logout}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
                {currentPage === "audit-logs" && (
                    <AuditLogs
                        token={token}
                        apiUrl={API_URL}
                        user={user}
                        onTokenExpired={() =>
                            logout(
                                "Token inválido ou expirado. Faça login novamente.",
                            )
                        }
                    />
                )}
            </main>
        </div>
    );
}

export default App;
