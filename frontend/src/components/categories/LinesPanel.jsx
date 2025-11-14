import React from "react";
import "./LinesPanel.css";

export default function LinesPanel({
    selectedCategory,
    lines,
    onCreateLine,
    onEditLine,
    onDeleteLine,
    onClose,
}) {
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
                            Linhas de {selectedCategory.name}
                        </h2>
                        <p className="lines-panel-subtitle">
                            {lines.length}{" "}
                            {lines.length === 1 ? "linha" : "linhas"}
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
                        + Nova Linha
                    </button>

                    {lines.length === 0 ? (
                        <div className="lines-panel-no-lines">
                            <p>Nenhuma linha cadastrada para esta categoria</p>
                        </div>
                    ) : (
                        <div className="lines-panel-list">
                            {lines.map((line) => (
                                <div key={line.id} className="lines-panel-item">
                                    <span className="lines-panel-item-name">
                                        {line.line}
                                    </span>
                                    <div className="lines-panel-item-actions">
                                        <button
                                            onClick={() => onEditLine(line)}
                                            className="lines-panel-icon-button"
                                            title="Editar"
                                        >
                                            <svg
                                                width="20"
                                                height="20"
                                                viewBox="0 0 24 24"
                                                fill="none"
                                                stroke="#3498db"
                                                strokeWidth="2"
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                            >
                                                <path d="M12 20h9" />
                                                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z" />
                                            </svg>
                                        </button>
                                        <button
                                            onClick={() =>
                                                onDeleteLine(line.id, line.line)
                                            }
                                            className="lines-panel-icon-button"
                                            title="Deletar"
                                        >
                                            <svg
                                                width="20"
                                                height="20"
                                                viewBox="0 0 24 24"
                                                fill="none"
                                                stroke="#e74c3c"
                                                strokeWidth="2"
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                            >
                                                <polyline points="3 6 5 6 21 6"></polyline>
                                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m5 0V4a2 2 0 0 1 2-2h0a2 2 0 0 1 2 2v2"></path>
                                                <line
                                                    x1="10"
                                                    y1="11"
                                                    x2="10"
                                                    y2="17"
                                                ></line>
                                                <line
                                                    x1="14"
                                                    y1="11"
                                                    x2="14"
                                                    y2="17"
                                                ></line>
                                            </svg>
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
