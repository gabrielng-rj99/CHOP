/*
 * Client Hub Open Project
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

/**
 * Theme API service for managing user theme settings
 * Provides secure communication with the backend for theme persistence
 */
const themeApi = {
    /**
     * Get the current user's theme settings
     * @param {string} apiUrl - Base API URL
     * @param {string} token - JWT access token
     * @param {function} onTokenExpired - Callback for expired token
     * @returns {Promise<Object>} Theme settings with permissions
     */
    getUserTheme: async (apiUrl, token, onTokenExpired) => {
        if (!token) {
            throw new Error("Token não fornecido");
        }

        const response = await fetch(`${apiUrl}/user/theme`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(
                errorData.error || "Erro ao carregar configurações de tema",
            );
        }

        return await response.json();
    },

    /**
     * Update the current user's theme settings
     * @param {string} apiUrl - Base API URL
     * @param {string} token - JWT access token
     * @param {Object} themeSettings - Theme settings to save
     * @param {function} onTokenExpired - Callback for expired token
     * @returns {Promise<Object>} Updated theme settings
     */
    updateUserTheme: async (apiUrl, token, themeSettings, onTokenExpired) => {
        if (!token) {
            throw new Error("Token não fornecido");
        }

        // Validate required fields
        if (!themeSettings || typeof themeSettings !== "object") {
            throw new Error("Configurações de tema inválidas");
        }

        // Sanitize and validate color values on client side
        const sanitizedSettings = themeApi.sanitizeThemeSettings(themeSettings);

        const response = await fetch(`${apiUrl}/user/theme`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(sanitizedSettings),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (response.status === 403) {
            throw new Error(
                "Você não tem permissão para alterar configurações de tema",
            );
        }

        if (response.status === 400) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || "Dados de tema inválidos");
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(
                errorData.error || "Erro ao salvar configurações de tema",
            );
        }

        return await response.json();
    },

    /**
     * Get theme permissions (root only)
     * @param {string} apiUrl - Base API URL
     * @param {string} token - JWT access token
     * @param {function} onTokenExpired - Callback for expired token
     * @returns {Promise<Object>} Theme permissions
     */
    getThemePermissions: async (apiUrl, token, onTokenExpired) => {
        if (!token) {
            throw new Error("Token não fornecido");
        }

        const response = await fetch(`${apiUrl}/settings/theme-permissions`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (response.status === 403) {
            throw new Error(
                "Apenas usuários root podem acessar permissões de tema",
            );
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(
                errorData.error || "Erro ao carregar permissões de tema",
            );
        }

        return await response.json();
    },

    /**
     * Update theme permissions (root only)
     * @param {string} apiUrl - Base API URL
     * @param {string} token - JWT access token
     * @param {Object} permissions - Permission settings
     * @param {boolean} permissions.users_can_edit_theme - Allow users to edit theme
     * @param {boolean} permissions.admins_can_edit_theme - Allow admins to edit theme
     * @param {function} onTokenExpired - Callback for expired token
     * @returns {Promise<Object>} Updated permissions
     */
    updateThemePermissions: async (
        apiUrl,
        token,
        permissions,
        onTokenExpired,
    ) => {
        if (!token) {
            throw new Error("Token não fornecido");
        }

        if (!permissions || typeof permissions !== "object") {
            throw new Error("Permissões inválidas");
        }

        const response = await fetch(`${apiUrl}/settings/theme-permissions`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                users_can_edit_theme: Boolean(permissions.users_can_edit_theme),
                admins_can_edit_theme: Boolean(
                    permissions.admins_can_edit_theme,
                ),
            }),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (response.status === 403) {
            throw new Error(
                "Apenas usuários root podem alterar permissões de tema",
            );
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(
                errorData.error || "Erro ao atualizar permissões de tema",
            );
        }

        return await response.json();
    },

    /**
     * Sanitize theme settings before sending to server
     * @param {Object} settings - Raw theme settings
     * @returns {Object} Sanitized settings
     */
    sanitizeThemeSettings: (settings) => {
        const sanitized = {};

        // Theme preset - sanitize string
        if (settings.theme_preset !== undefined) {
            sanitized.theme_preset = String(settings.theme_preset || "default")
                .trim()
                .substring(0, 100)
                .replace(/[<>]/g, ""); // Remove potential XSS characters
        }

        // Theme mode - validate enum
        const validModes = ["light", "dark", "system"];
        if (settings.theme_mode !== undefined) {
            const mode = String(settings.theme_mode).toLowerCase().trim();
            sanitized.theme_mode = validModes.includes(mode) ? mode : "system";
        }

        // Color blind mode - validate enum
        const validColorBlindModes = [
            "none",
            "protanopia",
            "deuteranopia",
            "tritanopia",
        ];
        if (settings.color_blind_mode !== undefined) {
            const mode = String(settings.color_blind_mode).toLowerCase().trim();
            sanitized.color_blind_mode = validColorBlindModes.includes(mode)
                ? mode
                : "none";
        }

        // High contrast - boolean
        if (settings.high_contrast !== undefined) {
            sanitized.high_contrast = Boolean(settings.high_contrast);
        }

        // Dyslexic font - boolean
        if (settings.dyslexic_font !== undefined) {
            sanitized.dyslexic_font = Boolean(settings.dyslexic_font);
        }

        // Layout mode - validate enum
        const validLayoutModes = ["standard", "full", "centralized"];
        if (settings.layout_mode !== undefined) {
            const mode = String(settings.layout_mode || "standard")
                .toLowerCase()
                .trim();
            sanitized.layout_mode = validLayoutModes.includes(mode)
                ? mode
                : "standard";
        }

        // Font fields - sanitize string, properly handle null values
        const fontFields = ["font_general", "font_title", "font_table_title"];
        fontFields.forEach((field) => {
            if (settings[field] !== undefined) {
                // If value is null, empty, or the string "null", set to null/undefined (don't send)
                if (
                    settings[field] === null ||
                    settings[field] === "" ||
                    settings[field] === "null"
                ) {
                    // Do not include in sanitized object if null/empty
                } else {
                    sanitized[field] = String(settings[field])
                        .trim()
                        .replace(/[<>]/g, "");
                }
            }
        });

        // Color fields - validate hex format
        const colorFields = [
            "primary_color",
            "secondary_color",
            "background_color",
            "surface_color",
            "text_color",
            "text_secondary_color",
            "border_color",
        ];

        const hexColorRegex = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/;

        colorFields.forEach((field) => {
            if (settings[field] !== undefined && settings[field] !== null) {
                const color = String(settings[field]).trim();
                if (color !== "" && hexColorRegex.test(color)) {
                    sanitized[field] = color;
                }
                // If invalid or empty, do not include
            }
        });

        return sanitized;
    },

    /**
     * Validate a single hex color value
     * @param {string} color - Color value to validate
     * @returns {boolean} True if valid hex color
     */
    isValidHexColor: (color) => {
        if (!color || typeof color !== "string") return false;
        return /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/.test(color.trim());
    },

    /**
     * Convert theme settings from API format to frontend format
     * @param {Object} apiSettings - Settings from API
     * @returns {Object} Frontend-compatible settings
     */
    apiToFrontend: (apiSettings) => {
        if (!apiSettings) return null;

        return {
            preset: apiSettings.theme_preset || "default",
            mode: apiSettings.theme_mode || "system",
            primaryColor: apiSettings.primary_color || null,
            secondaryColor: apiSettings.secondary_color || null,
            backgroundColor: apiSettings.background_color || null,
            surfaceColor: apiSettings.surface_color || null,
            textColor: apiSettings.text_color || null,
            textSecondaryColor: apiSettings.text_secondary_color || null,
            borderColor: apiSettings.border_color || null,
            highContrast: apiSettings.high_contrast || false,
            colorBlindMode: apiSettings.color_blind_mode || "none",
            dyslexicFont: apiSettings.dyslexic_font || false,
            fontGeneral: apiSettings.font_general || "System",
            fontTitle: apiSettings.font_title || "System",
            fontTableTitle: apiSettings.font_table_title || "System",
        };
    },

    /**
     * Convert theme settings from frontend format to API format
     * @param {Object} frontendSettings - Settings from frontend
     * @returns {Object} API-compatible settings
     */
    frontendToApi: (frontendSettings) => {
        if (!frontendSettings) return null;

        return {
            theme_preset: frontendSettings.preset || "default",
            theme_mode: frontendSettings.mode || "system",
            layout_mode: frontendSettings.layoutMode || "standard",
            primary_color: frontendSettings.primaryColor || null,
            secondary_color: frontendSettings.secondaryColor || null,
            background_color: frontendSettings.backgroundColor || null,
            surface_color: frontendSettings.surfaceColor || null,
            text_color: frontendSettings.textColor || null,
            text_secondary_color: frontendSettings.textSecondaryColor || null,
            border_color: frontendSettings.borderColor || null,
            high_contrast: frontendSettings.highContrast || false,
            color_blind_mode: frontendSettings.colorBlindMode || "none",
            dyslexic_font: frontendSettings.dyslexicFont || false,
            font_general: frontendSettings.fontGeneral || null,
            font_title: frontendSettings.fontTitle || null,
            font_table_title: frontendSettings.fontTableTitle || null,
        };
    },
};

export { themeApi };
