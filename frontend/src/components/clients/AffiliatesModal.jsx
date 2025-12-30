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

import React from "react";
import { formatDate } from "../../utils/clientHelpers";

export default function AffiliatesModal({
    showAffiliates,
    selectedClient,
    affiliates,
    affiliateForm,
    setAffiliateForm,
    selectedAffiliate,
    handleAffiliateSubmit,
    editAffiliate,
    deleteAffiliate,
    cancelAffiliateEdit,
    closeAffiliatesModal,
}) {
    if (!showAffiliates || !selectedClient) return null;

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
                        Afiliados de {selectedClient.name}
                    </h2>
                    <button
                        onClick={closeAffiliatesModal}
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
                    onSubmit={handleAffiliateSubmit}
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
                        {selectedAffiliate
                            ? "Editar Afiliado"
                            : "Adicionar Afiliado"}
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
                                value={affiliateForm.name}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
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
                                value={affiliateForm.relationship}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
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
                                value={affiliateForm.birth_date}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
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
                                value={affiliateForm.phone}
                                onChange={(e) =>
                                    setAffiliateForm({
                                        ...affiliateForm,
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
                        {selectedAffiliate && (
                            <button
                                type="button"
                                onClick={cancelAffiliateEdit}
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
                            {selectedAffiliate
                                ? "Salvar Alterações"
                                : "Adicionar Afiliado"}
                        </button>
                    </div>
                </form>

                {affiliates.length === 0 ? (
                    <div
                        style={{
                            padding: "40px",
                            textAlign: "center",
                            color: "#7f8c8d",
                        }}
                    >
                        Nenhum afiliado cadastrado
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
                            Lista de Afiliados
                        </h3>
                        <div
                            style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: "12px",
                            }}
                        >
                            {affiliates.map((affiliate) => (
                                <div
                                    key={affiliate.id}
                                    style={{
                                        padding: "16px",
                                        border: "1px solid #ecf0f1",
                                        borderRadius: "8px",
                                        background:
                                            selectedAffiliate?.id ===
                                            affiliate.id
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
                                            {affiliate.name}
                                        </div>
                                        <div
                                            style={{
                                                fontSize: "14px",
                                                color: "#7f8c8d",
                                            }}
                                        >
                                            {affiliate.relationship}
                                            {affiliate.birth_date &&
                                                ` • ${formatDate(affiliate.birth_date)}`}
                                            {affiliate.phone &&
                                                ` • ${affiliate.phone}`}
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
                                                editAffiliate(affiliate)
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
                                                deleteAffiliate(affiliate.id)
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
                        onClick={closeAffiliatesModal}
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
