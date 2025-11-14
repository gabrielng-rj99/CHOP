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
                                            className="lines-panel-button lines-panel-button-edit"
                                            title="Editar linha"
                                        >
                                            ✏️
                                        </button>
                                        <button
                                            onClick={() =>
                                                onDeleteLine(line.id, line.line)
                                            }
                                            className="lines-panel-button lines-panel-button-delete"
                                            title="Deletar linha"
                                        >
                                            🗑️
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
