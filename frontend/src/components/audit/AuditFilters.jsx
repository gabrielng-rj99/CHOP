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

import React, { useState } from "react";
import "./AuditFilters.css";
import { useConfig } from "../../contexts/ConfigContext";

export default function AuditFilters({ filters, setFilters, onApply }) {
    const { config } = useConfig();
    const labels = config.labels || {};
    const [isExpanded, setIsExpanded] = useState(false);

    const handleChange = (field, value) => {
        const newFilters = {
            ...filters,
            [field]: value,
        };
        setFilters(newFilters);
        // Apply filters immediately with the new filters object
        onApply(newFilters);
    };

    const handleDateChange = (field, value) => {
        setFilters((prev) => ({
            ...prev,
            [field]: value,
        }));
    };

    const handleClear = () => {
        setFilters({
            resource: "",
            operation: "",
            adminId: "",
            adminSearch: "",
            status: "",
            ipAddress: "",
            resourceId: "",
            resourceSearch: "",
            changedData: "",
            startDate: "",
            endDate: "",
            requestMethod: "",
            requestPath: "",
            responseCode: "",
            executionTimeMs: "",
            errorMessage: "",
        });
    };

    const hasActiveFilters = Object.values(filters).some(
        (value) => value !== "",
    );

    return (
        <div className="audit-filters-container">
            <div
                className="audit-filters-header"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="audit-filters-header-left">
                    <span className="audit-filters-expand-icon">
                        {isExpanded ? "▼" : "▶"}
                    </span>
                    <h3 className="audit-filters-title">Filtros Avançados</h3>
                    {hasActiveFilters && !isExpanded && (
                        <span className="audit-filters-active-badge">
                            Filtros ativos
                        </span>
                    )}
                </div>
                <span className="audit-filters-toggle-hint">
                    {isExpanded
                        ? "Clique para recolher"
                        : "Clique para expandir"}
                </span>
            </div>

            {isExpanded && (
                <div className="audit-filters-content">
                    <div className="audit-filters-grid">
                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Entidade
                            </label>
                            <select
                                value={filters.resource}
                                onChange={(e) =>
                                    handleChange("resource", e.target.value)
                                }
                                className="audit-filters-select"
                            >
                                <option value="">Todas as entidades</option>
                                <option value="auth">Autenticação</option>
                                <option value="user">
                                    {labels.user || "Usuários"}
                                </option>
                                <option value="client">
                                    {labels.client || "Clientes"}
                                </option>
                                <option value="contract">
                                    {labels.contract || "Contratos"}
                                </option>
                                <option value="category">
                                    {labels.category || "Categorias"}
                                </option>
                                <option value="subcategory">
                                    {labels.subcategory || "Subcategorias"}
                                </option>
                                <option value="affiliate">
                                    {labels.affiliate || "Afiliados"}
                                </option>
                                <option value="role">Cargos</option>
                                <option value="dashboard_config">
                                    Dashboard
                                </option>
                                <option value="global_theme">
                                    Tema Global
                                </option>
                            </select>
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Operação
                            </label>
                            <select
                                value={filters.operation}
                                onChange={(e) =>
                                    handleChange("operation", e.target.value)
                                }
                                className="audit-filters-select"
                            >
                                <option value="">Todas as operações</option>
                                <option value="login">Login</option>
                                <option value="create">Criar</option>
                                <option value="read">Ler</option>
                                <option value="update">Atualizar</option>
                                <option value="delete">Deletar</option>
                            </select>
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Status
                            </label>
                            <select
                                value={filters.status}
                                onChange={(e) =>
                                    handleChange("status", e.target.value)
                                }
                                className="audit-filters-select"
                            >
                                <option value="">Todos os status</option>
                                <option value="success">Sucesso</option>
                                <option value="error">Erro</option>
                            </select>
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Entidade (UUID ou Nome)
                            </label>
                            <input
                                type="text"
                                placeholder="UUID ou nome da entidade"
                                value={filters.resourceSearch}
                                onChange={(e) =>
                                    handleChange(
                                        "resourceSearch",
                                        e.target.value,
                                    )
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Admin (UUID ou Nome)
                            </label>
                            <input
                                type="text"
                                placeholder="UUID ou nome do admin"
                                value={filters.adminSearch}
                                onChange={(e) =>
                                    handleChange("adminSearch", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Trecho Alterado
                            </label>
                            <input
                                type="text"
                                placeholder="Buscar nos dados modificados"
                                value={filters.changedData}
                                onChange={(e) =>
                                    handleChange("changedData", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Endereço IP
                            </label>
                            <input
                                type="text"
                                placeholder="Ex: 192.168.1.1"
                                value={filters.ipAddress}
                                onChange={(e) =>
                                    handleChange("ipAddress", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Data Inicial
                            </label>
                            <input
                                type="datetime-local"
                                value={filters.startDate}
                                onChange={(e) =>
                                    handleDateChange(
                                        "startDate",
                                        e.target.value,
                                    )
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Data Final
                            </label>
                            <input
                                type="datetime-local"
                                value={filters.endDate}
                                onChange={(e) =>
                                    handleDateChange("endDate", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Método HTTP
                            </label>
                            <select
                                value={filters.requestMethod}
                                onChange={(e) =>
                                    handleChange(
                                        "requestMethod",
                                        e.target.value,
                                    )
                                }
                                className="audit-filters-select"
                            >
                                <option value="">Todos os métodos</option>
                                <option value="GET">GET</option>
                                <option value="POST">POST</option>
                                <option value="PUT">PUT</option>
                                <option value="DELETE">DELETE</option>
                                <option value="PATCH">PATCH</option>
                            </select>
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Endpoint
                            </label>
                            <input
                                type="text"
                                placeholder="Ex: /api/clients"
                                value={filters.requestPath}
                                onChange={(e) =>
                                    handleChange("requestPath", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Código de Resposta
                            </label>
                            <input
                                type="number"
                                placeholder="Ex: 200"
                                value={filters.responseCode}
                                onChange={(e) =>
                                    handleChange("responseCode", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Tempo de Execução (ms)
                            </label>
                            <input
                                type="number"
                                placeholder="Ex: 100"
                                value={filters.executionTimeMs}
                                onChange={(e) =>
                                    handleChange(
                                        "executionTimeMs",
                                        e.target.value,
                                    )
                                }
                                className="audit-filters-input"
                            />
                        </div>

                        <div className="audit-filters-field">
                            <label className="audit-filters-label">
                                Mensagem de Erro
                            </label>
                            <input
                                type="text"
                                placeholder="Buscar na mensagem de erro"
                                value={filters.errorMessage}
                                onChange={(e) =>
                                    handleChange("errorMessage", e.target.value)
                                }
                                className="audit-filters-input"
                            />
                        </div>
                    </div>

                    <div className="audit-filters-button-group">
                        <button
                            onClick={handleClear}
                            className="audit-filters-button audit-filters-button-clear"
                        >
                            Limpar Filtros
                        </button>
                        <button
                            onClick={onApply}
                            className="audit-filters-button audit-filters-button-apply"
                        >
                            Aplicar Filtros
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
