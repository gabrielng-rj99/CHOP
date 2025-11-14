import React from "react";
import { formatDate } from "../../utils/clientHelpers";

export default function DependentsModal({
    showDependents,
    selectedClient,
    dependents,
    dependentForm,
    setDependentForm,
    selectedDependent,
    handleDependentSubmit,
    editDependent,
    deleteDependent,
    cancelDependentEdit,
    closeDependentsModal,
}) {
    if (!showDependents || !selectedClient) return null;

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
            }}
        >
            <div
                style={{
                    background: "white",
                    borderRadius: "8px",
                    padding: "30px",
                    width: "90%",
                    maxWidth: "800px",
                    maxHeight: "90vh",
                    overflow: "auto",
                }}
            >
                <div
                    style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "24px",
                    }}
                >
                    <h2
                        style={{
                            margin: 0,
                            fontSize: "24px",
                            color: "#2c3e50",
                        }}
                    >
                        Dependentes de {selectedClient.name}
                    </h2>
                    <button
                        onClick={closeDependentsModal}
                        style={{
                            background: "transparent",
                            border: "none",
                            fontSize: "24px",
                            cursor: "pointer",
                            color: "#7f8c8d",
                        }}
                    >
                        ×
                    </button>
                </div>

                <form
                    onSubmit={handleDependentSubmit}
                    style={{
                        marginBottom: "30px",
                        padding: "20px",
                        background: "#f8f9fa",
                        borderRadius: "8px",
                    }}
                >
                    <h3
                        style={{
                            marginTop: 0,
                            marginBottom: "16px",
                            fontSize: "18px",
                            color: "#2c3e50",
                        }}
                    >
                        {selectedDependent
                            ? "Editar Dependente"
                            : "Adicionar Dependente"}
                    </h3>

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns: "2fr 1fr",
                            gap: "12px",
                            marginBottom: "12px",
                        }}
                    >
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "6px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#2c3e50",
                                }}
                            >
                                Nome *
                            </label>
                            <input
                                type="text"
                                value={dependentForm.name}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        name: e.target.value,
                                    })
                                }
                                required
                                style={{
                                    width: "100%",
                                    padding: "8px",
                                    border: "1px solid #ddd",
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
                                    marginBottom: "6px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#2c3e50",
                                }}
                            >
                                Parentesco *
                            </label>
                            <input
                                type="text"
                                value={dependentForm.relationship}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        relationship: e.target.value,
                                    })
                                }
                                required
                                placeholder="Filho, cônjuge..."
                                style={{
                                    width: "100%",
                                    padding: "8px",
                                    border: "1px solid #ddd",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>
                    </div>

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr",
                            gap: "12px",
                            marginBottom: "16px",
                        }}
                    >
                        <div>
                            <label
                                style={{
                                    display: "block",
                                    marginBottom: "6px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#2c3e50",
                                }}
                            >
                                Data de Nascimento
                            </label>
                            <input
                                type="date"
                                value={dependentForm.birth_date}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        birth_date: e.target.value,
                                    })
                                }
                                style={{
                                    width: "100%",
                                    padding: "8px",
                                    border: "1px solid #ddd",
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
                                    marginBottom: "6px",
                                    fontSize: "14px",
                                    fontWeight: "500",
                                    color: "#2c3e50",
                                }}
                            >
                                Telefone
                            </label>
                            <input
                                type="tel"
                                value={dependentForm.phone}
                                onChange={(e) =>
                                    setDependentForm({
                                        ...dependentForm,
                                        phone: e.target.value,
                                    })
                                }
                                placeholder="+5511999999999"
                                style={{
                                    width: "100%",
                                    padding: "8px",
                                    border: "1px solid #ddd",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>
                    </div>

                    <div style={{ display: "flex", gap: "12px" }}>
                        {selectedDependent && (
                            <button
                                type="button"
                                onClick={cancelDependentEdit}
                                style={{
                                    padding: "8px 16px",
                                    background: "white",
                                    color: "#7f8c8d",
                                    border: "1px solid #ddd",
                                    borderRadius: "4px",
                                    cursor: "pointer",
                                    fontSize: "14px",
                                }}
                            >
                                Cancelar Edição
                            </button>
                        )}
                        <button
                            type="submit"
                            style={{
                                padding: "8px 16px",
                                background: "#27ae60",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "14px",
                                fontWeight: "600",
                            }}
                        >
                            {selectedDependent
                                ? "Salvar Alterações"
                                : "Adicionar Dependente"}
                        </button>
                    </div>
                </form>

                {dependents.length === 0 ? (
                    <div
                        style={{
                            padding: "40px",
                            textAlign: "center",
                            color: "#7f8c8d",
                        }}
                    >
                        Nenhum dependente cadastrado
                    </div>
                ) : (
                    <div>
                        <h3
                            style={{
                                marginBottom: "16px",
                                fontSize: "18px",
                                color: "#2c3e50",
                            }}
                        >
                            Lista de Dependentes
                        </h3>
                        <div
                            style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: "12px",
                            }}
                        >
                            {dependents.map((dependent) => (
                                <div
                                    key={dependent.id}
                                    style={{
                                        padding: "16px",
                                        border: "1px solid #ecf0f1",
                                        borderRadius: "8px",
                                        background:
                                            selectedDependent?.id ===
                                            dependent.id
                                                ? "#e8f4f8"
                                                : "white",
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                    }}
                                >
                                    <div>
                                        <div
                                            style={{
                                                fontSize: "16px",
                                                fontWeight: "500",
                                                color: "#2c3e50",
                                                marginBottom: "4px",
                                            }}
                                        >
                                            {dependent.name}
                                        </div>
                                        <div
                                            style={{
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {dependent.relationship}
                                            {dependent.birth_date &&
                                                ` • ${formatDate(dependent.birth_date)}`}
                                            {dependent.phone &&
                                                ` • ${dependent.phone}`}
                                        </div>
                                    </div>
                                    <div
                                        style={{
                                            display: "flex",
                                            gap: "8px",
                                        }}
                                    >
                                        <button
                                            onClick={() =>
                                                editDependent(dependent)
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                background: "#3498db",
                                                color: "white",
                                                border: "none",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                                fontSize: "12px",
                                            }}
                                        >
                                            Editar
                                        </button>
                                        <button
                                            onClick={() =>
                                                deleteDependent(dependent.id)
                                            }
                                            style={{
                                                padding: "6px 12px",
                                                background: "#e74c3c",
                                                color: "white",
                                                border: "none",
                                                borderRadius: "4px",
                                                cursor: "pointer",
                                                fontSize: "12px",
                                            }}
                                        >
                                            Deletar
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div
                    style={{
                        marginTop: "24px",
                        paddingTop: "20px",
                        borderTop: "1px solid #ecf0f1",
                    }}
                >
                    <button
                        onClick={closeDependentsModal}
                        style={{
                            padding: "10px 24px",
                            background: "#7f8c8d",
                            color: "white",
                            border: "none",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "14px",
                        }}
                    >
                        Fechar
                    </button>
                </div>
            </div>
        </div>
    );
}
