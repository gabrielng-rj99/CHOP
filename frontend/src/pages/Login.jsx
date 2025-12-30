/*
 * This file is part of Client Hub Open Project.
 * Copyright (C) 2025 Client Hub Contributors
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
import "./styles/Login.css";

export default function Login({ onLogin }) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [sessionExpiredError, setSessionExpiredError] = useState(false);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        // Verificar se veio de uma sessão expirada
        const params = new URLSearchParams(window.location.search);
        if (params.get("session_expired") === "true") {
            setSessionExpiredError(true);
            // Limpar o parâmetro da URL
            window.history.replaceState(
                {},
                document.title,
                window.location.pathname,
            );
            // Limpar a mensagem após 15 segundos
            setTimeout(() => setSessionExpiredError(false), 15000);
        }
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setLoading(true);

        try {
            await onLogin(username, password);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <h1 className="login-title">
                    Client Hub<br></br>
                    Open Project
                </h1>
                <p className="login-subtitle">Gerenciador de Entidades FLOSS</p>

                {sessionExpiredError && (
                    <div className="login-session-expired">
                        Sua sessão expirou devido ao token inválido. <br></br>
                        Por favor, faça login novamente.
                    </div>
                )}
                {error && <div className="login-error">{error}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="login-form-group">
                        <label className="login-label">Usuário</label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            disabled={loading}
                            className="login-input"
                            placeholder="Digite seu usuário"
                        />
                    </div>

                    <div className="login-form-group">
                        <label className="login-label">Senha</label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            disabled={loading}
                            className="login-input"
                            placeholder="Digite sua senha"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="login-button"
                    >
                        {loading ? "Entrando..." : "Entrar"}
                    </button>
                </form>

                <p className="login-footer">
                    © Gabriel Gomes 2025.
                    <br></br> Todos os direitos reservados
                </p>
            </div>
        </div>
    );
}
