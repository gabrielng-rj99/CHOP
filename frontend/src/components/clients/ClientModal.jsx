import React from "react";

export default function ClientModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    handleSubmit,
    closeModal,
}) {
    if (!showModal) return null;

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
                    maxWidth: "600px",
                    maxHeight: "90vh",
                    overflow: "auto",
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
                    {modalMode === "create" ? "Novo Cliente" : "Editar Cliente"}
                </h2>

                <form onSubmit={handleSubmit}>
                    <div style={{ marginBottom: "16px" }}>
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
                            value={formData.name}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    name: e.target.value,
                                })
                            }
                            required
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr",
                            gap: "16px",
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
                                CPF/CNPJ
                            </label>
                            <input
                                type="text"
                                value={formData.registration_id}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        registration_id: e.target.value,
                                    })
                                }
                                style={{
                                    width: "100%",
                                    padding: "10px",
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
                                Apelido/Nome Fantasia
                            </label>
                            <input
                                type="text"
                                value={formData.nickname}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        nickname: e.target.value,
                                    })
                                }
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ddd",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>
                    </div>

                    <div style={{ marginBottom: "16px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "6px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#2c3e50",
                            }}
                        >
                            Data de Nascimento/Fundação
                        </label>
                        <input
                            type="date"
                            value={formData.birth_date}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    birth_date: e.target.value,
                                })
                            }
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr",
                            gap: "16px",
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
                                Email
                            </label>
                            <input
                                type="email"
                                value={formData.email}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        email: e.target.value,
                                    })
                                }
                                style={{
                                    width: "100%",
                                    padding: "10px",
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
                                value={formData.phone}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        phone: e.target.value,
                                    })
                                }
                                placeholder="+5511999999999"
                                style={{
                                    width: "100%",
                                    padding: "10px",
                                    border: "1px solid #ddd",
                                    borderRadius: "4px",
                                    fontSize: "14px",
                                    boxSizing: "border-box",
                                }}
                            />
                        </div>
                    </div>

                    <div style={{ marginBottom: "16px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "6px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#2c3e50",
                            }}
                        >
                            Endereço
                        </label>
                        <input
                            type="text"
                            value={formData.address}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    address: e.target.value,
                                })
                            }
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    <div style={{ marginBottom: "16px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "6px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#2c3e50",
                            }}
                        >
                            Preferência de Contato
                        </label>
                        <select
                            value={formData.contact_preference}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    contact_preference: e.target.value,
                                })
                            }
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        >
                            <option value="">Selecione...</option>
                            <option value="whatsapp">WhatsApp</option>
                            <option value="email">Email</option>
                            <option value="phone">Telefone</option>
                            <option value="sms">SMS</option>
                            <option value="outros">Outros</option>
                        </select>
                    </div>

                    <div style={{ marginBottom: "16px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "6px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#2c3e50",
                            }}
                        >
                            Tags (separadas por vírgula)
                        </label>
                        <input
                            type="text"
                            value={formData.tags}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    tags: e.target.value,
                                })
                            }
                            placeholder="vip, corporativo, etc"
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                            }}
                        />
                    </div>

                    <div style={{ marginBottom: "24px" }}>
                        <label
                            style={{
                                display: "block",
                                marginBottom: "6px",
                                fontSize: "14px",
                                fontWeight: "500",
                                color: "#2c3e50",
                            }}
                        >
                            Observações
                        </label>
                        <textarea
                            value={formData.notes}
                            onChange={(e) =>
                                setFormData({
                                    ...formData,
                                    notes: e.target.value,
                                })
                            }
                            rows={4}
                            style={{
                                width: "100%",
                                padding: "10px",
                                border: "1px solid #ddd",
                                borderRadius: "4px",
                                fontSize: "14px",
                                boxSizing: "border-box",
                                resize: "vertical",
                            }}
                        />
                    </div>

                    <div
                        style={{
                            display: "flex",
                            gap: "12px",
                            justifyContent: "flex-end",
                        }}
                    >
                        <button
                            type="button"
                            onClick={closeModal}
                            style={{
                                padding: "10px 24px",
                                background: "white",
                                color: "#7f8c8d",
                                border: "1px solid #ddd",
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
                            {modalMode === "create"
                                ? "Criar Cliente"
                                : "Salvar Alterações"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
