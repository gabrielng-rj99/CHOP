import React from "react";

export default function ContractModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    clients,
    categories,
    lines,
    dependents,
    onSubmit,
    onClose,
    onCategoryChange,
    onClientChange,
}) {
    if (!showModal) return null;

    const activeClients = clients.filter((c) => !c.archived_at);

    return (
        <div
            style={{
                position: "fixed",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: "rgba(0,0,0,0.5)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 1000,
                overflowY: "auto",
                padding: "20px",
            }}
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: "white",
                    borderRadius: "8px",
                    padding: "32px",
                    width: "90%",
                    maxWidth: "600px",
                    maxHeight: "90vh",
                    overflowY: "auto",
                }}
            >
                <h2
                    style={{
                        marginTop: 0,
                        marginBottom: "24px",
                        fontSize: "24px",
                        color: "#2c3e50",
                    }}
                >
                    {modalMode === "create" ? "Novo Contrato" : "Editar Contrato"}
                </h2>

                <form onSubmit={onSubmit}>
                    <div style={{ display: "grid", gap: "20px" }}>
                        {/* Cliente */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Cliente *
                            </label>
                            <select
                                value={formData.client_id}
                                onChange={(e) => {
                                    setFormData({
                                        ...formData,
                                        client_id: e.target.value,
                                        dependent_id: "",
                                    });
                                    onClientChange(e.target.value);
                                }}
                                required
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            >
                                <option value="">Selecione um cliente</option>
                                {activeClients.map((client) => (
                                    <option key={client.id} value={client.id}>
                                        {client.name} {client.nickname && `(${client.nickname})`}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {/* Dependente */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Dependente (Opcional)
                            </label>
                            <select
                                value={formData.dependent_id}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        dependent_id: e.target.value,
                                    })
                                }
                                disabled={!formData.client_id || dependents.length === 0}
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                    opacity: !formData.client_id || dependents.length === 0 ? 0.6 : 1,
                                }}
                            >
                                <option value="">Nenhum dependente</option>
                                {dependents.map((dep) => (
                                    <option key={dep.id} value={dep.id}>
                                        {dep.name}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {/* Categoria */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Categoria *
                            </label>
                            <select
                                value={formData.category_id}
                                onChange={(e) => {
                                    setFormData({
                                        ...formData,
                                        category_id: e.target.value,
                                        line_id: "",
                                    });
                                    onCategoryChange(e.target.value);
                                }}
                                required
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            >
                                <option value="">Selecione uma categoria</option>
                                {categories.map((cat) => (
                                    <option key={cat.id} value={cat.id}>
                                        {cat.name}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {/* Linha */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Linha *
                            </label>
                            <select
                                value={formData.line_id}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        line_id: e.target.value,
                                    })
                                }
                                disabled={!formData.category_id || lines.length === 0}
                                required
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                    opacity: !formData.category_id || lines.length === 0 ? 0.6 : 1,
                                }}
                            >
                                <option value="">Selecione uma linha</option>
                                {lines.map((line) => (
                                    <option key={line.id} value={line.id}>
                                        {line.line}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {/* Modelo */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Modelo
                            </label>
                            <input
                                type="text"
                                value={formData.model}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        model: e.target.value,
                                    })
                                }
                                placeholder="Ex: Plano Básico, Premium, etc."
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>

                        {/* Chave do Produto */}
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "8px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#495057",
                                }}
                            >
                                Chave do Produto
                            </label>
                            <input
                                type="text"
                                value={formData.product_key}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        product_key: e.target.value,
                                    })
                                }
                                placeholder="Ex: KEY-12345"
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ced4da",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>

                        {/* Datas */}
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                            <div>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "8px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#495057",
                                    }}
                                >
                                    Data de Início *
                                </label>
                                <input
                                    type="date"
                                    value={formData.start_date}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            start_date: e.target.value,
                                        })
                                    }
                                    required
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ced4da",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>
                            <div>
                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "8px",
                                        fontSize: "14px",
                                        fontWeight: "500",
                                        color: "#495057",
                                    }}
                                >
                                    Data de Vencimento *
                                </label>
                                <input
                                    type="date"
                                    value={formData.end_date}
                                    onChange={(e) =>
                                        setFormData({
                                            ...formData,
                                            end_date: e.target.value,
                                        })
                                    }
                                    required
                                    style={{
                                        width: "100%",
                                        padding: "10px",
                                        border: "1px solid #ced4da",
                                        borderRadius: "4px",
                                        fontSize: "14px",
                                        boxSizing: "border-box",
                                    }}
                                />
                            </div>
                        </div>
                    </div>

                    <div
                        style={{
                            display: "flex",
                            gap: "12px",
                            justifyContent: "flex-end",
                            marginTop: "32px",
                        }}
                    >
                        <button
                            type="button"
                            onClick={onClose}
                            style={{
                                padding: "10px 24px",
                                background: "#95a5a6",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                            }}
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            style={{
                                padding: "10px 24px",
                                background: "#27ae60",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                                fontWeight: "600",
                            }}
                        >
                            {modalMode === "create" ? "Criar Contrato" : "Salvar Alterações"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
