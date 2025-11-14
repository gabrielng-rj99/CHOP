import React from "react";
import "./AuditFilters.css";

export default function AuditFilters({ filters, setFilters, onApply }) {
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

    return (
        <div className="audit-filters-container">
            <h3 className="audit-filters-title">Filtros Avançados</h3>

            <div className="audit-filters-grid">
                <div className="audit-filters-field">
                    <label className="audit-filters-label">Entidade</label>
                    <select
                        value={filters.entity}
                        onChange={(e) => handleChange("entity", e.target.value)}
                        className="audit-filters-select"
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

                <div className="audit-filters-field">
                    <label className="audit-filters-label">Operação</label>
                    <select
                        value={filters.operation}
                        onChange={(e) =>
                            handleChange("operation", e.target.value)
                        }
                        className="audit-filters-select"
                    >
                        <option value="">Todas as operações</option>
                        <option value="create">Criar</option>
                        <option value="read">Ler</option>
                        <option value="update">Atualizar</option>
                        <option value="delete">Deletar</option>
                    </select>
                </div>

                <div className="audit-filters-field">
                    <label className="audit-filters-label">Status</label>
                    <select
                        value={filters.status}
                        onChange={(e) => handleChange("status", e.target.value)}
                        className="audit-filters-select"
                    >
                        <option value="">Todos os status</option>
                        <option value="success">Sucesso</option>
                        <option value="error">Erro</option>
                    </select>
                </div>

                <div className="audit-filters-field">
                    <label className="audit-filters-label">
                        ID da Entidade
                    </label>
                    <input
                        type="text"
                        placeholder="UUID da entidade"
                        value={filters.entityId}
                        onChange={(e) =>
                            handleChange("entityId", e.target.value)
                        }
                        className="audit-filters-input"
                    />
                </div>

                <div className="audit-filters-field">
                    <label className="audit-filters-label">Endereço IP</label>
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
                    <label className="audit-filters-label">ID do Admin</label>
                    <input
                        type="text"
                        placeholder="UUID do admin"
                        value={filters.adminId}
                        onChange={(e) =>
                            handleChange("adminId", e.target.value)
                        }
                        className="audit-filters-input"
                    />
                </div>

                <div className="audit-filters-field">
                    <label className="audit-filters-label">Data Inicial</label>
                    <input
                        type="datetime-local"
                        value={filters.startDate}
                        onChange={(e) =>
                            handleDateChange("startDate", e.target.value)
                        }
                        className="audit-filters-input"
                    />
                </div>

                <div className="audit-filters-field">
                    <label className="audit-filters-label">Data Final</label>
                    <input
                        type="datetime-local"
                        value={filters.endDate}
                        onChange={(e) =>
                            handleDateChange("endDate", e.target.value)
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
    );
}
