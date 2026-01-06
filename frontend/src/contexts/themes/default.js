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

// DEFAULT THEME - Tema Padrão (formerly standard blue)
export const defaultTheme = {
    default: {
        name: "Tema Padrão",
        light: {
            buttonPrimary: "#3498db",
            buttonSecondary: "#2c3e50",
            bgPage: "#f8f9fa",
            bgCard: "#ffffff",
            textPrimary: "#222222",
            textSecondary: "#444444",
            borderDefault: "#cbd5e0",
            // CSS :root uses --secondary-color for sidebar bg
            textNav: "#ffffff",
            bgNavbar: "#2c3e50",
            textTitle: "#2c3e50",
            textNavActive: "#f8f9fa",
        },
        dark: {
            buttonPrimary: "#3498db",
            // CSS .dark-mode inherits --secondary-color #2c3e50 unless overridden
            buttonSecondary: "#2c3e50",
            bgPage: "#1a202c",
            bgCard: "#2d3748",
            textPrimary: "#f7fafc",
            textSecondary: "#a0aec0",
            borderDefault: "#4a5568",
            textNav: "#ffffff",
            // CSS .dark-mode uses --secondary-color #2c3e50 for sidebar bg
            bgNavbar: "#2c3e50",
            // CSS .dark-mode sets --page-title-color to #f7fafc
            textTitle: "#f7fafc",
            textNavActive: "#f7fafc",
        },
    },
};
