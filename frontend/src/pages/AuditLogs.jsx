import React, { useState, useEffect } from "react";
import { auditApi } from "../api/auditApi";
import { usersApi } from "../api/usersApi";
import AuditFilters from "../components/audit/AuditFilters";
import AuditLogsTable from "../components/audit/AuditLogsTable";
import Pagination from "../components/common/Pagination";

export default function AuditLogs({ token, apiUrl, user }) {
    const [logs, setLogs] = useState([]);
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [totalLogs, setTotalLogs] = useState(0);
    const [currentPage, setCurrentPage] = useState(1);
    const [logsPerPage, setLogsPerPage] = useState(20);

    const [filters, setFilters] = useState({
        entity: "",
        operation: "",
        adminId: "",
        adminSearch: "",
        entitySearch: "",
        changedData: "",
        status: "",
        ipAddress: "",
        entityId: "",
        startDate: "",
        endDate: "",
    });

    useEffect(() => {
        loadUsers();
        loadLogs();
    }, []);

    useEffect(() => {
        setCurrentPage(1);
        loadLogs();
    }, [filters, logsPerPage]);

    const loadUsers = async () => {
        try {
            const userData = await usersApi.loadUsers(apiUrl, token);
            setUsers(userData);
        } catch (err) {
            console.error("Erro ao carregar usuários:", err);
        }
    };

    const loadLogs = async () => {
        setLoading(true);
        setError("");
        try {
            const offset = (currentPage - 1) * logsPerPage;
            const filterParams = {
                entity: filters.entity || undefined,
                operation: filters.operation || undefined,
                admin_id: filters.adminId || undefined,
                admin_search: filters.adminSearch || undefined,
                entity_search: filters.entitySearch || undefined,
                changed_data: filters.changedData || undefined,
                status: filters.status || undefined,
                ip_address: filters.ipAddress || undefined,
                entity_id: filters.entityId || undefined,
                start_date: filters.startDate
                    ? new Date(filters.startDate).toISOString()
                    : undefined,
                end_date: filters.endDate
                    ? new Date(filters.endDate).toISOString()
                    : undefined,
                limit: logsPerPage,
                offset: offset,
            };

            const response = await auditApi.getAuditLogs(
                apiUrl,
                token,
                filterParams,
            );
            setLogs(response.data || []);
            setTotalLogs(response.total || 0);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleFilterChange = (newFilters) => {
        setFilters(newFilters);
    };

    const handleApplyFilters = () => {
        setCurrentPage(1);
        loadLogs();
    };

    const handleViewDetail = (log) => {
        // Future: Open a modal with detailed information
        console.log("Viewing log detail:", log);
    };

    const handleExport = async () => {
        try {
            const filterParams = {
                entity: filters.entity || undefined,
                operation: filters.operation || undefined,
                admin_id: filters.adminId || undefined,
                admin_search: filters.adminSearch || undefined,
                entity_search: filters.entitySearch || undefined,
                changed_data: filters.changedData || undefined,
            };

            const data = await auditApi.exportAuditLogs(
                apiUrl,
                token,
                filterParams,
            );
            const json = JSON.stringify(data, null, 2);
            const blob = new Blob([json], { type: "application/json" });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `audit_logs_${new Date().getTime()}.json`;
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            setError("Erro ao exportar logs");
        }
    };

    const containerStyle = {
        padding: "0",
    };

    const headerStyle = {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "30px",
    };

    const titleStyle = {
        fontSize: "32px",
        color: "#2c3e50",
        margin: 0,
    };

    const buttonGroupStyle = {
        display: "flex",
        gap: "12px",
    };

    const buttonStyle = {
        padding: "10px 20px",
        background: "#3498db",
        color: "white",
        border: "none",
        borderRadius: "4px",
        cursor: "pointer",
        fontSize: "14px",
        fontWeight: "600",
    };

    const secondaryButtonStyle = {
        ...buttonStyle,
        background: "white",
        color: "#3498db",
        border: "1px solid #3498db",
    };

    if (!user || user.role !== "full_admin") {
        return (
            <div style={{ textAlign: "center", padding: "60px" }}>
                <div style={{ fontSize: "18px", color: "#e74c3c" }}>
                    Acesso negado. Apenas full_admin pode acessar logs de
                    auditoria.
                </div>
            </div>
        );
    }

    return (
        <div style={containerStyle}>
            <div style={headerStyle}>
                <h1 style={titleStyle}>Logs de Auditoria</h1>
                <div style={buttonGroupStyle}>
                    <button onClick={loadLogs} style={secondaryButtonStyle}>
                        Atualizar
                    </button>
                    <button onClick={handleExport} style={secondaryButtonStyle}>
                        Exportar JSON
                    </button>
                </div>
            </div>

            {error && (
                <div
                    style={{
                        background: "#fee",
                        color: "#c33",
                        padding: "16px",
                        borderRadius: "4px",
                        border: "1px solid #fcc",
                        marginBottom: "20px",
                    }}
                >
                    {error}
                </div>
            )}

            <AuditFilters
                filters={filters}
                setFilters={setFilters}
                onApply={handleApplyFilters}
            />

            <div
                style={{
                    background: "white",
                    borderRadius: "8px",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                    border: "1px solid #ecf0f1",
                    overflow: "hidden",
                }}
            >
                <AuditLogsTable
                    logs={logs}
                    onViewDetail={handleViewDetail}
                    loading={loading}
                />
            </div>

            <Pagination
                currentPage={currentPage}
                totalItems={totalLogs}
                itemsPerPage={logsPerPage}
                onPageChange={setCurrentPage}
                onItemsPerPageChange={setLogsPerPage}
            />
        </div>
    );
}
