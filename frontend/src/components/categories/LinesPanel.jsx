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
import "./LinesPanel.css";
import { useConfig } from "../../contexts/ConfigContext";
import EditIcon from "../../assets/icons/edit.svg";
import TrashIcon from "../../assets/icons/trash.svg";
import ArchiveIcon from "../../assets/icons/archive.svg";
import UnarchiveIcon from "../../assets/icons/unarchive.svg";

export default function LinesPanel({
    selectedCategory,
    lines,
    onCreateLine,
    onEditLine,
    onDeleteLine,
    onArchiveLine,
    onUnarchiveSubcategory,
    onClose,
}) {
    const { config } = useConfig();
    const { labels } = config;
    const SUBCATEGORY_LABEL = labels.subcategories || "Linhas";
    const SUBCATEGORY_SINGLE = labels.subcategory || "Linha";
    const NEW_SUBCATEGORY_LABEL = "+ Nova " + (labels.subcategory || "Linha");

    if (!selectedCategory) {
        return null;
    }

    return (
        <>
            <div className="lines-panel-overlay" onClick={onClose}></div>
            <div className="lines-panel">
                <div className="lines-panel-header">
                    <div>
                        <h2 className="lines-panel-title">
                            {SUBCATEGORY_LABEL} de {selectedCategory.name}
                        </h2>
                        <p className="lines-panel-subtitle">
                            {lines.length}{" "}
                            {lines.length === 1
                                ? SUBCATEGORY_SINGLE.toLowerCase()
                                : SUBCATEGORY_LABEL.toLowerCase()}
                        </p>
                    </div>
                    <button onClick={onClose} className="lines-panel-close">
                        ✕
                    </button>
                </div>

                <div className="lines-panel-content">
                    <button
                        onClick={onCreateLine}
                        className="lines-panel-button-new"
                    >
                        {NEW_SUBCATEGORY_LABEL}
                    </button>

                    {lines.length === 0 ? (
                        <div className="lines-panel-no-lines">
                            <p>
                                Nenhuma {SUBCATEGORY_SINGLE.toLowerCase()}{" "}
                                cadastrada para esta categoria
                            </p>
                        </div>
                    ) : (
                        <div className="lines-panel-list">
                            {lines.map((line) => {
                                const isArchived = !!line.archived_at;
                                return (
                                    <div
                                        key={line.id}
                                        className="lines-panel-item"
                                    >
                                        <div
                                            style={{
                                                display: "flex",
                                                alignItems: "center",
                                                gap: "12px",
                                            }}
                                        >
                                            <span className="lines-panel-item-name">
                                                {line.line}
                                            </span>
                                            {isArchived && (
                                                <span
                                                    style={{
                                                        background: "#95a5a620",
                                                        color: "#95a5a6",
                                                        padding: "2px 8px",
                                                        borderRadius: "8px",
                                                        fontSize: "11px",
                                                        fontWeight: "600",
                                                    }}
                                                >
                                                    Arquivado
                                                </span>
                                            )}
                                        </div>
                                        <div className="lines-panel-item-actions">
                                            <button
                                                onClick={() => onEditLine(line)}
                                                className="lines-panel-icon-button"
                                                title="Editar"
                                            >
                                                <img
                                                    src={EditIcon}
                                                    alt="Editar"
                                                    style={{
                                                        width: "24px",
                                                        height: "24px",
                                                        filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                                    }}
                                                />
                                            </button>
                                            {isArchived ? (
                                                <button
                                                    onClick={() =>
                                                        onUnarchiveSubcategory(
                                                            line.id,
                                                            line.line,
                                                        )
                                                    }
                                                    className="lines-panel-icon-button"
                                                    title="Desarquivar"
                                                >
                                                    <img
                                                        src={UnarchiveIcon}
                                                        alt="Desarquivar"
                                                        style={{
                                                            width: "24px",
                                                            height: "24px",
                                                            filter: "invert(62%) sepia(34%) saturate(760%) hue-rotate(88deg) brightness(93%) contrast(81%)",
                                                        }}
                                                    />
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() =>
                                                        onArchiveLine(
                                                            line.id,
                                                            line.line,
                                                        )
                                                    }
                                                    className="lines-panel-icon-button"
                                                    title="Arquivar"
                                                >
                                                    <img
                                                        src={ArchiveIcon}
                                                        alt="Arquivar"
                                                        style={{
                                                            width: "24px",
                                                            height: "24px",
                                                            filter: "invert(64%) sepia(81%) saturate(455%) hue-rotate(359deg) brightness(98%) contrast(91%)",
                                                        }}
                                                    />
                                                </button>
                                            )}
                                            <button
                                                onClick={() =>
                                                    onDeleteLine(
                                                        line.id,
                                                        line.line,
                                                    )
                                                }
                                                className="lines-panel-icon-button"
                                                title="Deletar"
                                            >
                                                <img
                                                    src={TrashIcon}
                                                    alt="Deletar"
                                                    style={{
                                                        width: "24px",
                                                        height: "24px",
                                                        filter: "invert(37%) sepia(93%) saturate(1447%) hue-rotate(342deg) brightness(94%) contrast(88%)",
                                                    }}
                                                />
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
