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
import { useConfig } from "../../contexts/ConfigContext";
import "./ThemeToggle.css";

export default function ThemeToggle() {
    const { themeMode, setThemeMode, resolvedMode } = useConfig();

    // Cycle: system -> light -> dark -> system
    const cycleMode = () => {
        if (themeMode === "system") setThemeMode("light");
        else if (themeMode === "light") setThemeMode("dark");
        else setThemeMode("system");
    };

    const getIcon = () => {
        if (themeMode === "system") return "💻"; // Or a system icon
        if (themeMode === "light") return "☀️";
        return "🌙";
    };

    const getLabel = () => {
        if (themeMode === "system") return "Auto";
        if (themeMode === "light") return "Claro";
        return "Escuro";
    };

    return (
        <button
            onClick={cycleMode}
            className="theme-toggle-pill"
            title={`Tema atual: ${getLabel()} (Clique para alternar)`}
            aria-label="Alternar tema"
        >
            <span className="toggle-icon">{getIcon()}</span>
            <span className="toggle-label">{getLabel()}</span>
        </button>
    );
}
