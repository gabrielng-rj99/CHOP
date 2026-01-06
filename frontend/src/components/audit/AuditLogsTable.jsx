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
import "./AuditLogsTable.css";

// Adiciona prop users para resolver nomes de usuários
export default function AuditLogsTable({
    logs,
    users = [],
    onViewDetail,
    loading,
}) {
    const [expandedId, setExpandedId] = useState(null);

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "40px" }}>
                <div
                    style={{
                        fontSize: "16px",
                        color: "var(--secondary-text-color, #7f8c8d)",
                    }}
                >
                    Carregando logs...
                </div>
            </div>
        );
    }

    if (!logs || logs.length === 0) {
        return (
            <div style={{ textAlign: "center", padding: "40px" }}>
                <div className="audit-logs-table-empty">
                    Nenhum log de auditoria encontrado
                </div>
            </div>
        );
    }

    const getOperationColor = (operation) => {
        switch (operation) {
            case "create":
                return "#27ae60";
            case "update":
                return "#f39c12";
            case "delete":
                return "#e74c3c";
            case "read":
                return "#3498db";
            default:
                return "#95a5a6";
        }
    };

    const getOperationLabel = (operation) => {
        switch (operation) {
            case "create":
                return "Criou";
            case "update":
                return "Atualizou";
            case "delete":
                return "Deletou";
            case "read":
                return "Leu";
            case "login":
                return "Login";
            default:
                return operation;
        }
    };

    const getStatusColor = (status) => {
        return status === "success" ? "#27ae60" : "#e74c3c";
    };

    const getStatusLabel = (status) => {
        return status === "success" ? "Sucesso" : "Erro";
    };

    const getClientLabel = (client) => {
        const labels = {
            auth: "Autenticação",
            user: "Usuário",
            client: "Cliente",
            contract: "Acordo",
            line: "Linha",
            category: "Categoria",
            affiliate: "Afiliado",
        };
        return labels[client] || client;
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        // Parse date correctly to avoid timezone issues
        if (dateString.match(/^\d{4}-\d{2}-\d{2}/)) {
            const [datePart, timePart] = dateString.split("T");
            const [year, month, day] = datePart.split("-");
            if (timePart) {
                const [hour, minute, second] = timePart.split(":");
                const secondClean = second ? second.split(".")[0] : "00";
                return `${day}/${month}/${year} ${hour}:${minute}:${secondClean}`;
            }
            return `${day}/${month}/${year}`;
        }
        const date = new Date(dateString);
        return date.toLocaleString("pt-BR", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    };

    const formatJSON = (jsonString) => {
        try {
            if (!jsonString) return "N/A";
            let obj = JSON.parse(jsonString);
            // Se o resultado ainda for uma string, fazer parse novamente
            if (typeof obj === "string") {
                obj = JSON.parse(obj);
            }
            return JSON.stringify(obj, null, 4);
        } catch {
            return jsonString;
        }
    };

    const getChangeContext = (log) => {
        if (!log.old_value && !log.new_value) return "N/A";

        try {
            // Parse inicial
            let oldData = log.old_value ? JSON.parse(log.old_value) : null;
            let newData = log.new_value ? JSON.parse(log.new_value) : null;

            // Se o resultado ainda for uma string, fazer parse novamente (double-encoded JSON)
            if (typeof oldData === "string") {
                oldData = JSON.parse(oldData);
            }
            if (typeof newData === "string") {
                newData = JSON.parse(newData);
            }

            // Para operação de criação - mostrar apenas o nome/identificador criado
            if (log.operation === "create" && newData) {
                // Sempre buscar por 'name' primeiro, depois outros campos
                if (newData.name) {
                    return String(newData.name).substring(0, 40);
                }
                if (newData.username) {
                    return String(newData.username).substring(0, 40);
                }
                if (newData.display_name) {
                    return String(newData.display_name).substring(0, 40);
                }
                if (newData.line) {
                    return String(newData.line).substring(0, 40);
                }
                return "N/A";
            }

            // Para operação de atualização - mostrar o nome/identificador do registro atualizado
            if (log.operation === "update") {
                const data = newData || oldData;
                if (!data) return "N/A";

                if (data.name) {
                    return String(data.name).substring(0, 40);
                }
                if (data.username) {
                    return String(data.username).substring(0, 40);
                }
                if (data.display_name) {
                    return String(data.display_name).substring(0, 40);
                }
                if (data.line) {
                    return String(data.line).substring(0, 40);
                }
                return "N/A";
            }

            // Para operação de deleção - mostrar apenas o nome/identificador deletado
            if (log.operation === "delete" && oldData) {
                if (oldData.name) {
                    return String(oldData.name).substring(0, 40);
                }
                if (oldData.username) {
                    return String(oldData.username).substring(0, 40);
                }
                if (oldData.display_name) {
                    return String(oldData.display_name).substring(0, 40);
                }
            }

            // fallback
            return "N/A";
        } catch {
            return "N/A";
        }
    };

    // NOVA FUNÇÃO: resolve objeto pelo usuário
    const getObjectLabel = (log) => {
        // Verifica client_id com diferentes possibilidades de nome de campo
        const clientId = log.client_id || log.clientId || log.ClientID;

        // Se for entidade usuário, tenta várias formas de resolver
        if (log.client === "user") {
            // Primeiro tenta extrair do old_value ou new_value (mais confiável)
            try {
                const oldValue =
                    typeof log.old_value === "string"
                        ? JSON.parse(log.old_value)
                        : log.old_value;
                const newValue =
                    typeof log.new_value === "string"
                        ? JSON.parse(log.new_value)
                        : log.new_value;

                // Prioriza new_value (criação/atualização)
                if (newValue?.username) return newValue.username;
                if (oldValue?.username) return oldValue.username;

                // Fallback para display_name
                if (newValue?.display_name) return newValue.display_name;
                if (oldValue?.display_name) return oldValue.display_name;
            } catch (e) {
                // Ignora erro de parse
            }

            // Se tiver client_id, tenta buscar na lista de users
            if (clientId) {
                const user = users.find((u) => u.id === clientId);
                if (user) {
                    return user.username || user.display_name || clientId;
                }
                // Se não encontrou, retorna o UUID
                return clientId.substring(0, 8) + "...";
            }
        }

        // Para entidade auth (login)
        if (log.client === "auth") {
            return "N/A";
        }

        // fallback para contexto de mudança
        return getChangeContext(log);
    };

    return (
        <div style={{ overflowX: "auto" }}>
            <table className="audit-logs-table">
                <thead>
                    <tr>
                        <th width="4%"></th>
                        <th width="16%">Data/Hora</th>
                        <th width="10%">Status</th>
                        <th width="14%">Admin</th>
                        <th width="10%">Operação</th>
                        <th width="10%">Entidade</th>
                        <th width="26%">Objeto</th>
                    </tr>
                </thead>
                <tbody>
                    {logs.map((log) => (
                        <React.Fragment key={log.id}>
                            <tr>
                                <td style={{ textAlign: "center" }}>
                                    <button
                                        onClick={() =>
                                            setExpandedId(
                                                expandedId === log.id
                                                    ? null
                                                    : log.id,
                                            )
                                        }
                                        className="audit-logs-expand-button"
                                        title={
                                            expandedId === log.id
                                                ? "Recolher"
                                                : "Expandir"
                                        }
                                    >
                                        {expandedId === log.id ? "−" : "+"}
                                    </button>
                                </td>
                                <td>{formatDate(log.timestamp)}</td>
                                <td>
                                    <span
                                        className={`audit-logs-status-badge ${log.status}`}
                                    >
                                        {getStatusLabel(log.status)}
                                    </span>
                                </td>
                                <td>
                                    {log.admin_username || (
                                        <span
                                            style={{
                                                color: "var(--secondary-text-color, #95a5a6)",
                                                fontStyle: "italic",
                                            }}
                                        >
                                            Deletado
                                        </span>
                                    )}
                                </td>
                                <td>
                                    <span
                                        className={`audit-logs-operation-badge ${log.operation}`}
                                    >
                                        {getOperationLabel(log.operation)}
                                    </span>
                                </td>
                                <td>{getClientLabel(log.client)}</td>
                                <td>{getObjectLabel(log)}</td>
                            </tr>
                            {expandedId === log.id && (
                                <tr>
                                    <td
                                        colSpan="6"
                                        className="audit-logs-expanded-row"
                                    >
                                        <div
                                            style={{
                                                display: "grid",
                                                gridTemplateColumns: "1fr 1fr",
                                                gap: "20px",
                                                marginBottom: "16px",
                                            }}
                                        >
                                            <div>
                                                <h4
                                                    style={{
                                                        margin: "0 0 12px 0",
                                                        color: "var(--primary-text-color, #2c3e50)",
                                                    }}
                                                >
                                                    Informações da Requisição
                                                </h4>
                                                <table
                                                    style={{
                                                        width: "100%",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    <tbody>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                    width: "40%",
                                                                }}
                                                            >
                                                                Método:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                }}
                                                            >
                                                                {log.request_method ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                }}
                                                            >
                                                                Endpoint:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                    wordBreak:
                                                                        "break-all",
                                                                }}
                                                            >
                                                                {log.request_path ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                }}
                                                            >
                                                                Status HTTP:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                }}
                                                            >
                                                                {log.response_code ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                }}
                                                            >
                                                                Tempo (ms):
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                }}
                                                            >
                                                                {log.execution_time_ms ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                    </tbody>
                                                </table>
                                            </div>
                                            <div>
                                                <h4
                                                    style={{
                                                        margin: "0 0 12px 0",
                                                        color: "var(--primary-text-color, #2c3e50)",
                                                    }}
                                                >
                                                    Informações do Cliente
                                                </h4>
                                                <table
                                                    style={{
                                                        width: "100%",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    <tbody>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                    width: "40%",
                                                                }}
                                                            >
                                                                IP:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                }}
                                                            >
                                                                {log.ip_address ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                }}
                                                            >
                                                                User-Agent:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                    fontSize:
                                                                        "11px",
                                                                    wordBreak:
                                                                        "break-all",
                                                                }}
                                                            >
                                                                {log.user_agent ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    fontWeight:
                                                                        "600",
                                                                    color: "var(--primary-text-color, #2c3e50)",
                                                                }}
                                                            >
                                                                Admin ID:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "var(--secondary-text-color, #34495e)",
                                                                    fontSize:
                                                                        "11px",
                                                                    wordBreak:
                                                                        "break-all",
                                                                }}
                                                            >
                                                                {log.admin_id ||
                                                                    "N/A"}
                                                            </td>
                                                        </tr>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>

                                        {(log.old_value || log.new_value) && (
                                            <div>
                                                <h4 className="audit-logs-changes-title">
                                                    Dados Alterados
                                                </h4>
                                                <div
                                                    style={{
                                                        display: "grid",
                                                        gridTemplateColumns:
                                                            "1fr 1fr",
                                                        gap: "16px",
                                                    }}
                                                >
                                                    {log.old_value && (
                                                        <div>
                                                            <h5
                                                                style={{
                                                                    margin: "0 0 8px 0",
                                                                    color: "var(--alert-error-text)",
                                                                    fontSize:
                                                                        "13px",
                                                                }}
                                                            >
                                                                Valor Anterior
                                                            </h5>
                                                            <pre
                                                                style={{
                                                                    background:
                                                                        "var(--diff-removed-bg)",
                                                                    padding:
                                                                        "12px",
                                                                    borderRadius:
                                                                        "4px",
                                                                    fontSize:
                                                                        "13px",
                                                                    overflow:
                                                                        "auto",
                                                                    maxHeight:
                                                                        "400px",
                                                                    color: "var(--diff-removed-text)",
                                                                    margin: 0,
                                                                    fontFamily:
                                                                        "'Courier New', monospace",
                                                                    lineHeight:
                                                                        "1.6",
                                                                    whiteSpace:
                                                                        "pre-wrap",
                                                                    wordBreak:
                                                                        "break-word",
                                                                }}
                                                            >
                                                                {formatJSON(
                                                                    log.old_value,
                                                                )}
                                                            </pre>
                                                        </div>
                                                    )}
                                                    {log.new_value && (
                                                        <div>
                                                            <h5
                                                                style={{
                                                                    margin: "0 0 8px 0",
                                                                    color: "var(--diff-added-text)",
                                                                    fontSize:
                                                                        "13px",
                                                                }}
                                                            >
                                                                Valor Novo
                                                            </h5>
                                                            <pre
                                                                style={{
                                                                    background:
                                                                        "var(--diff-added-bg)",
                                                                    padding:
                                                                        "12px",
                                                                    borderRadius:
                                                                        "4px",
                                                                    fontSize:
                                                                        "13px",
                                                                    overflow:
                                                                        "auto",
                                                                    maxHeight:
                                                                        "400px",
                                                                    color: "var(--diff-added-text)",
                                                                    margin: 0,
                                                                    fontFamily:
                                                                        "'Courier New', monospace",
                                                                    lineHeight:
                                                                        "1.6",
                                                                    whiteSpace:
                                                                        "pre-wrap",
                                                                    wordBreak:
                                                                        "break-word",
                                                                }}
                                                            >
                                                                {formatJSON(
                                                                    log.new_value,
                                                                )}
                                                            </pre>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )}

                                        {log.error_message && (
                                            <div
                                                style={{
                                                    marginTop: "16px",
                                                    padding: "12px",
                                                    background:
                                                        "var(--alert-error-bg)",
                                                    borderLeft:
                                                        "4px solid var(--alert-error-text)",
                                                    borderRadius: "4px",
                                                }}
                                            >
                                                <h5
                                                    style={{
                                                        margin: "0 0 8px 0",
                                                        color: "var(--diff-removed-text)",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    Mensagem de Erro
                                                </h5>
                                                <p
                                                    style={{
                                                        margin: 0,
                                                        color: "var(--diff-removed-text)",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    {log.error_message}
                                                </p>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            )}
                        </React.Fragment>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
