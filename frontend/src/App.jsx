import React, { useState, useEffect } from "react";
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

    useEffect(() => {
        const savedToken = localStorage.getItem("token");
        const savedUser = localStorage.getItem("user");

        if (savedToken && savedUser) {
            setToken(savedToken);
            setUser(JSON.parse(savedUser));
            setCurrentPage("dashboard");
        }
    }, []);

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
            setUser(userData);
            localStorage.setItem("token", data.data.token);
            localStorage.setItem("user", JSON.stringify(userData));
            setCurrentPage("dashboard");
        } catch (error) {
            throw error;
        }
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        setCurrentPage("login");
    };

    const navigate = (page) => {
        setCurrentPage(page);
    };

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
