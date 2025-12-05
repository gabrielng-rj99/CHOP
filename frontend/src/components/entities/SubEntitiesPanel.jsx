/*
 * This file is part of Entity Hub Open Project.
 * Copyright (C) 2025 Entity Hub Contributors
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
import "./SubEntitiesPanel.css";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";

export default function SubEntitiesPanel({
    selectedClient,
    dependents,
    onCreateDependent,
    onEditDependent,
    onDeleteDependent,
    onClose,
}) {
    if (!selectedClient) {
        return null;
    }

    return (
        <>
            <div className="dependents-panel-overlay" onClick={onClose}></div>
            <div className="dependents-panel">
                <div className="dependents-panel-header">
                    <div>
                        <h2 className="dependents-panel-title">
                            Dependentes de {selectedClient.name}
                        </h2>
                        <p className="dependents-panel-subtitle">
                            {dependents.length}{" "}
                            {dependents.length === 1
                                ? "dependente"
                                : "dependentes"}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="dependents-panel-close"
                    >
                        ✕
                    </button>
                </div>

                <div className="dependents-panel-content">
                    <button
                        onClick={onCreateDependent}
                        className="dependents-panel-button-new"
                    >
                        + Novo Dependente
                    </button>

                    {dependents.length === 0 ? (
                        <div className="dependents-panel-no-dependents">
                            <p>
                                Nenhum dependente cadastrado para este cliente
                            </p>
                        </div>
                    ) : (
                        <div className="dependents-panel-list">
                            {dependents.map((dependent) => (
                                <div
                                    key={dependent.id}
                                    className="dependents-panel-item"
                                >
                                    <div className="dependents-panel-item-info">
                                        <span className="dependents-panel-item-name">
                                            {dependent.name}
                                        </span>
                                        <span className="dependents-panel-item-relationship">
                                            {dependent.relationship}
                                        </span>
                                    </div>
                                    <div className="dependents-panel-item-actions">
                                        <button
                                            onClick={() =>
                                                onEditDependent(dependent)
                                            }
                                            className="dependents-panel-icon-button"
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
                                                onDeleteDependent(dependent.id)
                                            }
                                            className="dependents-panel-icon-button"
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
