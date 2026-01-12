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
import Select from "react-select";
import { useConfig } from "../../contexts/ConfigContext";
import "./ContractsModal.css";

export default function ContractModal({
    showModal,
    modalMode,
    formData,
    setFormData,
    clients,
    categories,
    lines,
    affiliates,
    onSubmit,
    onClose,
    onCategoryChange,
    onClientChange,
    error,
}) {
    const { config } = useConfig();
    const { labels } = config;

    if (!showModal) return null;

    const activeClients = clients.filter((c) => !c.archived_at);

    // Custom styles for react-select to match existing styles
    const customSelectStyles = {
        control: (provided, state) => ({
            ...provided,
            width: "100%",
            fontSize: "14px",
            border: "1px solid #ced4da",
            borderRadius: "4px",
            background: "white",
            color: "#333",
            cursor: "pointer",
            boxShadow: state.isFocused
                ? "0 0 0 1px #3498db"
                : provided.boxShadow,
            "&:hover": {
                borderColor: "#3498db",
            },
        }),
        option: (provided, state) => ({
            ...provided,
            backgroundColor: state.isSelected
                ? "#3498db"
                : state.isFocused
                  ? "#f8f9fa"
                  : "white",
            color: state.isSelected ? "white" : "#333",
            cursor: "pointer",
        }),
        menu: (provided) => ({
            ...provided,
            background: "white",
            border: "1px solid #ced4da",
            borderRadius: "4px",
        }),
        singleValue: (provided) => ({
            ...provided,
            color: "#333",
        }),
        placeholder: (provided) => ({
            ...provided,
            color: "#999",
        }),
        input: (provided) => ({
            ...provided,
            color: "#333",
        }),
    };

    // Convert date from yyyy-mm-dd to dd/mm/yyyy for display
    const formatDateForDisplay = (dateString) => {
        if (!dateString) return "";
        const [year, month, day] = dateString.split("-");
        return `${day}/${month}/${year}`;
    };

    // Convert date from dd/mm/yyyy to yyyy-mm-dd for API
    const formatDateForAPI = (dateString) => {
        if (!dateString) return "";
        const parts = dateString.replace(/\//g, "-").split("-");
        if (parts.length === 3) {
            const [day, month, year] = parts;
            if (year && year.length === 4) {
                return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
            }
        }
        return dateString;
    };

    const handleDateChange = (field, value) => {
        // Allow only numbers and /
        const cleaned = value.replace(/[^\d/]/g, "");

        // Auto-format as user types
        let formatted = cleaned;
        if (cleaned.length >= 2 && cleaned.charAt(2) !== "/") {
            formatted = cleaned.slice(0, 2) + "/" + cleaned.slice(2);
        }
        if (cleaned.length >= 5 && cleaned.charAt(5) !== "/") {
            const parts = formatted.split("/");
            if (parts.length >= 2) {
                formatted =
                    parts[0] +
                    "/" +
                    parts[1].slice(0, 2) +
                    "/" +
                    parts[1].slice(2);
            }
        }

        // Limit to dd/mm/yyyy format
        if (formatted.length > 10) {
            formatted = formatted.slice(0, 10);
        }

        setFormData({
            ...formData,
            [field]: formatted,
        });
    };

    // Labels with fallbacks
    const clientLabel = labels.client || "Cliente";
    const affiliateLabel = labels.affiliate || "Afiliado";
    const categoryLabel = labels.category || "Categoria";
    const subcategoryLabel = labels.subcategory || "Subcategoria";
    const modelLabel = labels.model || "Descrição";
    const itemKeyLabel = labels.item_key || "Identificador";
    const contractLabel = labels.contract || "Contrato";

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
                    {modalMode === "create"
                        ? `Novo ${contractLabel}`
                        : `Editar ${contractLabel}`}
                </h2>

                {error && (
                    <div
                        style={{
                            background: "#fee",
                            color: "#c33",
                            padding: "12px 16px",
                            borderRadius: "4px",
                            border: "1px solid #fcc",
                            marginBottom: "20px",
                            fontSize: "14px",
                        }}
                    >
                        {error}
                    </div>
                )}

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
                                {clientLabel} *
                            </label>
                            <Select
                                value={
                                    formData.client_id
                                        ? {
                                              value: formData.client_id,
                                              label:
                                                  activeClients.find(
                                                      (c) =>
                                                          c.id ===
                                                          formData.client_id,
                                                  )?.name +
                                                  (activeClients.find(
                                                      (c) =>
                                                          c.id ===
                                                          formData.client_id,
                                                  )?.nickname
                                                      ? ` (${
                                                            activeClients.find(
                                                                (c) =>
                                                                    c.id ===
                                                                    formData.client_id,
                                                            )?.nickname
                                                        })`
                                                      : ""),
                                          }
                                        : null
                                }
                                onChange={(selected) => {
                                    setFormData({
                                        ...formData,
                                        client_id: selected
                                            ? selected.value
                                            : "",
                                        affiliate_id: "",
                                    });
                                    onClientChange(
                                        selected ? selected.value : "",
                                    );
                                }}
                                options={[
                                    {
                                        value: "",
                                        label: `Selecione um ${clientLabel.toLowerCase()}`,
                                    },
                                    ...activeClients.map((client) => ({
                                        value: client.id,
                                        label: `${client.name}${
                                            client.nickname
                                                ? ` (${client.nickname})`
                                                : ""
                                        }`,
                                    })),
                                ]}
                                isSearchable={true}
                                placeholder={`Selecione um ${clientLabel.toLowerCase()}`}
                                styles={customSelectStyles}
                                required
                            />
                        </div>

                        {/* Afiliado */}
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
                                {affiliateLabel}
                                <span
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginLeft: "4px",
                                    }}
                                >
                                    (opcional)
                                </span>
                            </label>
                            <Select
                                value={
                                    formData.affiliate_id
                                        ? {
                                              value: formData.affiliate_id,
                                              label: affiliates.find(
                                                  (a) =>
                                                      a.id ===
                                                      formData.affiliate_id,
                                              )?.name,
                                          }
                                        : null
                                }
                                onChange={(selected) =>
                                    setFormData({
                                        ...formData,
                                        affiliate_id: selected
                                            ? selected.value
                                            : "",
                                    })
                                }
                                options={[
                                    {
                                        value: "",
                                        label: `Nenhum ${affiliateLabel.toLowerCase()}`,
                                    },
                                    ...affiliates.map((aff) => ({
                                        value: aff.id,
                                        label: aff.name,
                                    })),
                                ]}
                                isSearchable={true}
                                isDisabled={
                                    !formData.client_id ||
                                    affiliates.length === 0
                                }
                                placeholder={`Selecione um ${affiliateLabel.toLowerCase()}`}
                                styles={{
                                    ...customSelectStyles,
                                    control: (provided, state) => ({
                                        ...customSelectStyles.control(
                                            provided,
                                            state,
                                        ),
                                        opacity:
                                            !formData.client_id ||
                                            affiliates.length === 0
                                                ? 0.6
                                                : 1,
                                    }),
                                }}
                            />
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
                                {categoryLabel} *
                            </label>
                            <Select
                                value={
                                    formData.category_id
                                        ? {
                                              value: formData.category_id,
                                              label: categories.find(
                                                  (c) =>
                                                      c.id ===
                                                      formData.category_id,
                                              )?.name,
                                          }
                                        : null
                                }
                                onChange={(selected) => {
                                    setFormData({
                                        ...formData,
                                        category_id: selected
                                            ? selected.value
                                            : "",
                                        subcategory_id: "",
                                    });
                                    onCategoryChange(
                                        selected ? selected.value : "",
                                    );
                                }}
                                options={[
                                    {
                                        value: "",
                                        label: `Selecione uma ${categoryLabel.toLowerCase()}`,
                                    },
                                    ...categories.map((cat) => ({
                                        value: cat.id,
                                        label: cat.name,
                                    })),
                                ]}
                                isSearchable={true}
                                placeholder={`Selecione uma ${categoryLabel.toLowerCase()}`}
                                styles={customSelectStyles}
                                required
                            />
                        </div>

                        {/* Subcategoria/Linha */}
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
                                {subcategoryLabel} *
                            </label>
                            <Select
                                value={
                                    formData.subcategory_id
                                        ? {
                                              value: formData.subcategory_id,
                                              label: lines.find(
                                                  (l) =>
                                                      l.id ===
                                                      formData.subcategory_id,
                                              )?.name,
                                          }
                                        : null
                                }
                                onChange={(selected) =>
                                    setFormData({
                                        ...formData,
                                        subcategory_id: selected
                                            ? selected.value
                                            : "",
                                    })
                                }
                                options={[
                                    {
                                        value: "",
                                        label: `Selecione uma ${subcategoryLabel.toLowerCase()}`,
                                    },
                                    ...lines.map((line) => ({
                                        value: line.id,
                                        label: line.name,
                                    })),
                                ]}
                                isSearchable={true}
                                isDisabled={
                                    !formData.category_id || lines.length === 0
                                }
                                placeholder={`Selecione uma ${subcategoryLabel.toLowerCase()}`}
                                styles={{
                                    ...customSelectStyles,
                                    control: (provided, state) => ({
                                        ...customSelectStyles.control(
                                            provided,
                                            state,
                                        ),
                                        opacity:
                                            !formData.category_id ||
                                            lines.length === 0
                                                ? 0.6
                                                : 1,
                                    }),
                                }}
                                required
                            />
                        </div>

                        {/* Modelo/Descrição */}
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
                                {modelLabel}
                                <span
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginLeft: "4px",
                                    }}
                                >
                                    (opcional)
                                </span>
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

                        {/* Chave do Produto/Identificador */}
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
                                {itemKeyLabel}
                                <span
                                    style={{
                                        fontSize: "12px",
                                        color: "#7f8c8d",
                                        marginLeft: "4px",
                                    }}
                                >
                                    (opcional)
                                </span>
                            </label>
                            <input
                                type="text"
                                value={formData.item_key}
                                onChange={(e) =>
                                    setFormData({
                                        ...formData,
                                        item_key: e.target.value,
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
                        <div
                            style={{
                                display: "grid",
                                gridTemplateColumns: "1fr 1fr",
                                gap: "16px",
                            }}
                        >
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
                                    Data de Início
                                    <span
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginLeft: "4px",
                                        }}
                                    >
                                        (opcional)
                                    </span>
                                </label>
                                <input
                                    type="text"
                                    value={formData.start_date}
                                    onChange={(e) =>
                                        handleDateChange(
                                            "start_date",
                                            e.target.value,
                                        )
                                    }
                                    placeholder="dd/mm/aaaa"
                                    maxLength="10"
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
                                    Data de Vencimento
                                    <span
                                        style={{
                                            fontSize: "12px",
                                            color: "#7f8c8d",
                                            marginLeft: "4px",
                                        }}
                                    >
                                        (opcional)
                                    </span>
                                </label>
                                <input
                                    type="text"
                                    value={formData.end_date}
                                    onChange={(e) =>
                                        handleDateChange(
                                            "end_date",
                                            e.target.value,
                                        )
                                    }
                                    placeholder="dd/mm/aaaa"
                                    maxLength="10"
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

                        <div
                            style={{
                                fontSize: "12px",
                                color: "#7f8c8d",
                                marginTop: "-10px",
                            }}
                        >
                            <p style={{ margin: 0 }}>
                                💡 Dica: As datas são opcionais. {contractLabel}
                                s sem data de término são considerados
                                permanentes (ex: licenças vitalícias).
                            </p>
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
                            {modalMode === "create"
                                ? `Criar ${contractLabel}`
                                : "Salvar Alterações"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
