/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
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
import { useLastUpdate } from "../../hooks/useLastUpdate";

export default function RefreshButton({
    onClick,
    disabled = false,
    isLoading = false,
    onLoadStart = null,
    icon = "↻",
    label = null,
}) {
    const { relativeTime, recordUpdate } = useLastUpdate();

    const handleClick = async () => {
        if (onLoadStart) {
            onLoadStart();
        }
        recordUpdate();
        if (onClick) {
            await onClick();
        }
    };

    const displayLabel = isLoading ? "Atualizando..." : label || "Atualizar";

    return (
        <div
            style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "flex-end",
            }}
        >
            <button
                onClick={handleClick}
                className="refresh-button"
                disabled={disabled || isLoading}
                style={{
                    justifyContent: "center",
                    textAlign: "center",
                }}
            >
                <span
                    style={{
                        fontSize: "14px",
                        lineHeight: "1",
                        display: "flex",
                        alignItems: "center",
                    }}
                >
                    {icon}
                </span>
                {displayLabel}
            </button>
            {relativeTime && (
                <span className="update-timestamp">
                    última atualização {relativeTime}
                </span>
            )}
        </div>
    );
}
