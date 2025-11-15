import React, { useState } from "react";

export default function AuditLogsTable({ logs, onViewDetail, loading }) {
    const [expandedId, setExpandedId] = useState(null);

    if (loading) {
        return (
            <div style={{ textAlign: "center", padding: "40px" }}>
                <div style={{ fontSize: "16px", color: "#7f8c8d" }}>
                    Carregando logs...
                </div>
            </div>
        );
    }

    if (!logs || logs.length === 0) {
        return (
            <div style={{ textAlign: "center", padding: "40px" }}>
                <div style={{ fontSize: "16px", color: "#7f8c8d" }}>
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

    const getEntityLabel = (entity) => {
        const labels = {
            user: "Usuário",
            client: "Cliente",
            contract: "Contrato",
            line: "Linha",
            category: "Categoria",
            dependent: "Dependente",
        };
        return labels[entity] || entity;
    };

    const formatDate = (dateString) => {
        if (!dateString) return "-";
        // Parse date correctly to avoid timezone issues
        if (dateString.match(/^\d{4}-\d{2}-\d{2}/)) {
            const [datePart, timePart] = dateString.split("T");
            const [year, month, day] = datePart.split("-");
            if (timePart) {
                const [hour, minute, second] = timePart.split(":");
                return `${day}/${month}/${year} ${hour}:${minute}`;
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
                if (oldData.line) {
                    return String(oldData.line).substring(0, 40);
                }
                return "N/A";
            }

            return "N/A";
        } catch (error) {
            console.error("Erro ao processar contexto:", error, log);
            return "N/A";
        }
    };

    const tableStyle = {
        width: "100%",
        borderCollapse: "collapse",
        background: "white",
    };

    const headerStyle = {
        borderBottom: "2px solid #ecf0f1",
        padding: "16px",
        textAlign: "left",
        fontSize: "13px",
        fontWeight: "600",
        color: "#2c3e50",
        background: "#f8f9fa",
    };

    const rowStyle = {
        borderBottom: "1px solid #ecf0f1",
        padding: "12px 16px",
        fontSize: "14px",
        color: "#34495e",
    };

    const expandedRowStyle = {
        background: "#f8f9fa",
        padding: "20px",
    };

    return (
        <div style={{ overflowX: "auto" }}>
            <table style={tableStyle}>
                <thead>
                    <tr style={{ background: "#f8f9fa" }}>
                        <th style={headerStyle} width="4%"></th>
                        <th style={headerStyle} width="16%">
                            Data/Hora
                        </th>
                        <th style={headerStyle} width="10%">
                            Status
                        </th>
                        <th style={headerStyle} width="14%">
                            Admin
                        </th>
                        <th style={headerStyle} width="10%">
                            Operação
                        </th>
                        <th style={headerStyle} width="10%">
                            Entidade
                        </th>
                        <th style={headerStyle} width="26%">
                            Objeto
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {logs.map((log) => (
                        <React.Fragment key={log.id}>
                            <tr style={{ borderBottom: "1px solid #ecf0f1" }}>
                                <td
                                    style={{ ...rowStyle, textAlign: "center" }}
                                >
                                    <button
                                        onClick={() =>
                                            setExpandedId(
                                                expandedId === log.id
                                                    ? null
                                                    : log.id,
                                            )
                                        }
                                        style={{
                                            background: "none",
                                            border: "none",
                                            cursor: "pointer",
                                            fontSize: "18px",
                                            color: "#3498db",
                                            padding: "0",
                                            lineHeight: "1",
                                        }}
                                        title={
                                            expandedId === log.id
                                                ? "Recolher"
                                                : "Expandir"
                                        }
                                    >
                                        {expandedId === log.id ? "−" : "+"}
                                    </button>
                                </td>
                                <td style={rowStyle}>
                                    {formatDate(log.timestamp)}
                                </td>
                                <td style={rowStyle}>
                                    <span
                                        style={{
                                            background: getStatusColor(
                                                log.status,
                                            ),
                                            color: "white",
                                            padding: "4px 12px",
                                            borderRadius: "12px",
                                            fontSize: "12px",
                                            fontWeight: "600",
                                        }}
                                    >
                                        {getStatusLabel(log.status)}
                                    </span>
                                </td>
                                <td style={rowStyle}>
                                    {log.admin_username || (
                                        <span
                                            style={{
                                                color: "#95a5a6",
                                                fontStyle: "italic",
                                            }}
                                        >
                                            Deletado
                                        </span>
                                    )}
                                </td>
                                <td style={rowStyle}>
                                    <span
                                        style={{
                                            background: getOperationColor(
                                                log.operation,
                                            ),
                                            color: "white",
                                            padding: "4px 12px",
                                            borderRadius: "12px",
                                            fontSize: "12px",
                                            fontWeight: "600",
                                        }}
                                    >
                                        {getOperationLabel(log.operation)}
                                    </span>
                                </td>
                                <td style={rowStyle}>
                                    {getEntityLabel(log.entity)}
                                </td>
                                <td
                                    style={{
                                        ...rowStyle,
                                        fontSize: "13px",
                                        color: "#5a6c7d",
                                    }}
                                >
                                    {getChangeContext(log)}
                                </td>
                            </tr>
                            {expandedId === log.id && (
                                <tr>
                                    <td
                                        colSpan="6"
                                        style={{
                                            ...expandedRowStyle,
                                            padding: "20px",
                                        }}
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
                                                        color: "#2c3e50",
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
                                                                    color: "#2c3e50",
                                                                    width: "40%",
                                                                }}
                                                            >
                                                                Método:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                                    color: "#2c3e50",
                                                                }}
                                                            >
                                                                Endpoint:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                                    color: "#2c3e50",
                                                                }}
                                                            >
                                                                Status HTTP:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                                    color: "#2c3e50",
                                                                }}
                                                            >
                                                                Tempo (ms):
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                        color: "#2c3e50",
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
                                                                    color: "#2c3e50",
                                                                    width: "40%",
                                                                }}
                                                            >
                                                                IP:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                                    color: "#2c3e50",
                                                                }}
                                                            >
                                                                User-Agent:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                                    color: "#2c3e50",
                                                                }}
                                                            >
                                                                Admin ID:
                                                            </td>
                                                            <td
                                                                style={{
                                                                    padding:
                                                                        "6px 0",
                                                                    color: "#34495e",
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
                                                <h4
                                                    style={{
                                                        margin: "16px 0 12px 0",
                                                        color: "#2c3e50",
                                                    }}
                                                >
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
                                                                    color: "#e74c3c",
                                                                    fontSize:
                                                                        "13px",
                                                                }}
                                                            >
                                                                Valor Anterior
                                                            </h5>
                                                            <pre
                                                                style={{
                                                                    background:
                                                                        "#fff5f5",
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
                                                                    color: "#c0392b",
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
                                                                    color: "#27ae60",
                                                                    fontSize:
                                                                        "13px",
                                                                }}
                                                            >
                                                                Valor Novo
                                                            </h5>
                                                            <pre
                                                                style={{
                                                                    background:
                                                                        "#f0fdf4",
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
                                                                    color: "#1e7e34",
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
                                                    background: "#fee",
                                                    borderLeft:
                                                        "4px solid #e74c3c",
                                                    borderRadius: "4px",
                                                }}
                                            >
                                                <h5
                                                    style={{
                                                        margin: "0 0 8px 0",
                                                        color: "#c0392b",
                                                        fontSize: "13px",
                                                    }}
                                                >
                                                    Mensagem de Erro
                                                </h5>
                                                <p
                                                    style={{
                                                        margin: 0,
                                                        color: "#c0392b",
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
