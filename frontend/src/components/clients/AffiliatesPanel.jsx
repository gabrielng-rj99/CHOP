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
import "./AffiliatesPanel.css";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";

export default function AffiliatesPanel({
    selectedClient,
    affiliates,
    onCreateAffiliate,
    onEditAffiliate,
    onDeleteAffiliate,
    onClose,
}) {
    if (!selectedClient) {
        return null;
    }

    return (
        <>
            <div className="affiliates-panel-overlay" onClick={onClose}></div>
            <div className="affiliates-panel">
                <div className="affiliates-panel-header">
                    <div>
                        <h2 className="affiliates-panel-title">
                            Afiliados de {selectedClient.name}
                        </h2>
                        <p className="affiliates-panel-subtitle">
                            {affiliates.length}{" "}
                            {affiliates.length === 1 ? "afiliado" : "afiliados"}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="affiliates-panel-close"
                    >
                        ✕
                    </button>
                </div>

                <div className="affiliates-panel-content">
                    <button
                        onClick={onCreateAffiliate}
                        className="affiliates-panel-button-new"
                    >
                        + Novo Afiliado
                    </button>

                    {affiliates.length === 0 ? (
                        <div className="affiliates-panel-no-affiliates">
                            <p>Nenhum afiliado cadastrado para este cliente</p>
                        </div>
                    ) : (
                        <div className="affiliates-panel-list">
                            {affiliates.map((affiliate) => (
                                <div
                                    key={affiliate.id}
                                    className="affiliates-panel-item"
                                >
                                    <div className="affiliates-panel-item-info">
                                        <span className="affiliates-panel-item-name">
                                            {affiliate.name}
                                        </span>
                                        <span className="affiliates-panel-item-relationship">
                                            {affiliate.relationship}
                                        </span>
                                    </div>
                                    <div className="affiliates-panel-item-actions">
                                        <button
                                            onClick={() =>
                                                onEditAffiliate(affiliate)
                                            }
                                            className="affiliates-panel-icon-button"
                                            title="Editar"
                                        >
                                            <img
                                                src={EditIcon}
                                                alt="Editar"
                                                style={{
                                                    width: "20px",
                                                    height: "20px",
                                                    filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                                }}
                                            />
                                        </button>
                                        <button
                                            onClick={() =>
                                                onDeleteAffiliate(affiliate.id)
                                            }
                                            className="affiliates-panel-icon-button"
                                            title="Deletar"
                                        >
                                            <img
                                                src={TrashIcon}
                                                alt="Deletar"
                                                style={{
                                                    width: "20px",
                                                    height: "20px",
                                                    filter: "invert(37%) sepia(93%) saturate(1447%) hue-rotate(342deg) brightness(94%) contrast(88%)",
                                                }}
                                            />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
