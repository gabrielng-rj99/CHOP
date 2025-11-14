import React from "react";

export default function AuditFilters({
    filters,
    setFilters,
    onApply,
}) {
    const handleChange = (field, value) => {
        setFilters((prev) => ({
            ...prev,
            [field]: value,
        }));
    };

    const handleDateChange = (field, value) => {
        setFilters((prev) => ({
            ...prev,
            [field]: value,
        }));
    };

    const handleClear = () => {
        setFilters({
            entity: "",
            operation: "",
            adminId: "",
            status: "",
            ipAddress: "",
            entityId: "",
            startDate: "",
            endDate: "",
        });
    };

    const containerStyle = {
        background: "white",
        borderRadius: "8px",
        padding: "20px",
        marginBottom: "24px",
        border: "1px solid #ecf0f1",
        boxShadow: "0 2px 4px rgba(0,0,0,0.05)",
    };

    const gridStyle = {
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
        gap: "16px",
        marginBottom: "16px",
    };

    const fieldStyle = {
        display: "flex",
        flexDirection: "column",
        gap: "8px",
    };

    const labelStyle = {
        fontSize: "13px",
        fontWeight: "600",
        color: "#2c3e50",
    };

    const selectStyle = {
        padding: "10px 12px",
        border: "1px solid #ddd",
        borderRadius: "4px",
        fontSize: "14px",
        fontFamily: "inherit",
        backgroundColor: "white",
        cursor: "pointer",
    };

    const inputStyle = {
        padding: "10px 12px",
        border: "1px solid #ddd",
        borderRadius: "4px",
        fontSize: "14px",
        fontFamily: "inherit",
    };

    const buttonGroupStyle = {
        display: "flex",
        gap: "12px",
        justifyContent: "flex-end",
    };

    const applyButtonStyle = {
        padding: "10px 24px",
        background: "#3498db",
        color: "white",
        border: "none",
        borderRadius: "4px",
        cursor: "pointer",
        fontSize: "14px",
        fontWeight: "600",
    };

    const clearButtonStyle = {
        padding: "10px 24px",
        background: "white",
        color: "#3498db",
        border: "1px solid #3498db",
        borderRadius: "4px",
        cursor: "pointer",
        fontSize: "14px",
        fontWeight: "600",
    };

    return (
        <div style={containerStyle}>
            <h3 style={{ margin: "0 0 20px 0", color: "#2c3e50", fontSize: "16px" }}>
                Filtros Avançados
            </h3>

            <div style={gridStyle}>
                <div style={fieldStyle}>
                    <label style={labelStyle}>Entidade</label>
                    <select
                        value={filters.entity}
                        onChange={(e) => handleChange("entity", e.target.value)}
                        style={selectStyle}
                    >
                        <option value="">Todas as entidades</option>
                        <option value="user">Usuários</option>
                        <option value="client">Clientes</option>
                        <option value="contract">Contratos</option>
                        <option value="line">Linhas</option>
                        <option value="category">Categorias</option>
                        <option value="dependent">Dependentes</option>
                    </select>
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>Operação</label>
                    <select
                        value={filters.operation}
                        onChange={(e) => handleChange("operation", e.target.value)}
                        style={selectStyle}
                    >
                        <option value="">Todas as operações</option>
                        <option value="create">Criar</option>
                        <option value="read">Ler</option>
                        <option value="update">Atualizar</option>
                        <option value="delete">Deletar</option>
                    </select>
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>Status</label>
                    <select
                        value={filters.status}
                        onChange={(e) => handleChange("status", e.target.value)}
                        style={selectStyle}
                    >
                        <option value="">Todos os status</option>
                        <option value="success">Sucesso</option>
                        <option value="error">Erro</option>
                    </select>
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>ID da Entidade</label>
                    <input
                        type="text"
                        placeholder="UUID da entidade"
                        value={filters.entityId}
                        onChange={(e) => handleChange("entityId", e.target.value)}
                        style={inputStyle}
                    />
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>Endereço IP</label>
                    <input
                        type="text"
                        placeholder="Ex: 192.168.1.1"
                        value={filters.ipAddress}
                        onChange={(e) => handleChange("ipAddress", e.target.value)}
                        style={inputStyle}
                    />
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>ID do Admin</label>
                    <input
                        type="text"
                        placeholder="UUID do admin"
                        value={filters.adminId}
                        onChange={(e) => handleChange("adminId", e.target.value)}
                        style={inputStyle}
                    />
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>Data Inicial</label>
                    <input
                        type="datetime-local"
                        value={filters.startDate}
                        onChange={(e) => handleDateChange("startDate", e.target.value)}
                        style={inputStyle}
                    />
                </div>

                <div style={fieldStyle}>
                    <label style={labelStyle}>Data Final</label>
                    <input
                        type="datetime-local"
                        value={filters.endDate}
                        onChange={(e) => handleDateChange("endDate", e.target.value)}
                        style={inputStyle}
                    />
                </div>
            </div>

            <div style={buttonGroupStyle}>
                <button onClick={handleClear} style={clearButtonStyle}>
                    Limpar Filtros
                </button>
                <button onClick={onApply} style={applyButtonStyle}>
                    Aplicar Filtros
                </button>
            </div>
        </div>
    );
}
