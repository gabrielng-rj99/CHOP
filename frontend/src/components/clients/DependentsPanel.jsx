import React from "react";
import "./DependentsPanel.css";

export default function DependentsPanel({
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
                            {dependents.length === 1 ? "dependente" : "dependentes"}
                        </p>
                    </div>
                    <button onClick={onClose} className="dependents-panel-close">
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
                            <p>Nenhum dependente cadastrado para este cliente</p>
                        </div>
                    ) : (
                        <div className="dependents-panel-list">
                            {dependents.map((dependent) => (
                                <div key={dependent.id} className="dependents-panel-item">
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
                                            onClick={() => onEditDependent(dependent)}
                                            className="dependents-panel-icon-button"
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
                                                onDeleteDependent(dependent.id)
                                            }
                                            className="dependents-panel-icon-button"
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
