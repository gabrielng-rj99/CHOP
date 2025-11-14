import React from "react";
import "./LinesPanel.css";

export default function LinesPanel({
    selectedCategory,
    lines,
    onCreateLine,
    onEditLine,
    onDeleteLine,
}) {
    if (!selectedCategory) {
        return (
            <div className="lines-panel-empty">
                <p>Selecione uma categoria para ver suas linhas</p>
            </div>
        );
    }

    return (
        <div className="lines-panel">
            <div className="lines-panel-header">
                <h2 className="lines-panel-title">
                    Linhas de {selectedCategory.name}
                </h2>
                <button
                    onClick={onCreateLine}
                    className="lines-panel-button-new"
                >
                    + Nova Linha
                </button>
            </div>

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
                                >
                                    Editar
                                </button>
                                <button
                                    onClick={() =>
                                        onDeleteLine(line.id, line.line)
                                    }
                                    className="lines-panel-button lines-panel-button-delete"
                                >
                                    Deletar
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
