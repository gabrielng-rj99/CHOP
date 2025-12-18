/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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

import React, {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
} from "react";
import { THEME_PRESETS } from "./themes/index.js";
import { themeApi } from "../api/themeApi.js";

const ConfigContext = createContext();

export const useConfig = () => {
    const context = useContext(ConfigContext);
    if (!context) {
        throw new Error("useConfig must be used within a ConfigProvider");
    }
    return context;
};

// Re-export THEME_PRESETS for backward compatibility
export { THEME_PRESETS };

// Colorblind-Safe Palettes
const COLORBLIND_SAFE = {
    protanopia: {
        light: {
            buttonPrimary: "#0077bb",
            buttonSecondary: "#cc6677",
            bgPage: "#f0f4f8",
            bgCard: "#ffffff",
            textPrimary: "#1a1a1a",
            textSecondary: "#4a4a4a",
            borderDefault: "#88ccee",
        },
        dark: {
            buttonPrimary: "#88ccee",
            buttonSecondary: "#ee99aa",
            bgPage: "#1a1a1a",
            bgCard: "#2d2d2d",
            textPrimary: "#f0f4f8",
            textSecondary: "#cccccc",
            borderDefault: "#0077bb",
        },
    },
    deuteranopia: {
        light: {
            buttonPrimary: "#0077bb",
            buttonSecondary: "#ee7733",
            bgPage: "#f0f4f8",
            bgCard: "#ffffff",
            textPrimary: "#1a1a1a",
            textSecondary: "#4a4a4a",
            borderDefault: "#88ccee",
        },
        dark: {
            buttonPrimary: "#88ccee",
            buttonSecondary: "#ff9955",
            bgPage: "#1a1a1a",
            bgCard: "#2d2d2d",
            textPrimary: "#f0f4f8",
            textSecondary: "#cccccc",
            borderDefault: "#0077bb",
        },
    },
    tritanopia: {
        light: {
            buttonPrimary: "#ee3377",
            buttonSecondary: "#009988",
            bgPage: "#f0f4f8",
            bgCard: "#ffffff",
            textPrimary: "#1a1a1a",
            textSecondary: "#4a4a4a",
            borderDefault: "#cc3366",
        },
        dark: {
            buttonPrimary: "#ee7799",
            buttonSecondary: "#33bbaa",
            bgPage: "#1a1a1a",
            bgCard: "#2d2d2d",
            textPrimary: "#f0f4f8",
            textSecondary: "#cccccc",
            borderDefault: "#bb2255",
        },
    },
};

// Default Settings
const defaultSettings = {
    branding: {
        appName: "Entity Hub",
        logoUrl:
            "https://via.placeholder.com/150x50/3498db/ffffff?text=Entity+Hub",
        minimizedIconUrl:
            "https://via.placeholder.com/32x32/3498db/ffffff?text=EH",
        logoWideUrl: "",
        logoSquareUrl: "",
        useCustomLogo: false,
    },
    labels: {
        entity: "Cliente",
        entity_gender: "M",
        entities: "Clientes",
        agreement: "Contrato",
        agreement_gender: "M",
        agreements: "Contratos",
        category: "Categoria",
        category_gender: "F",
        categories: "Categorias",
        subcategory: "Subcategoria",
        subcategory_gender: "F",
        subcategories: "Subcategorias",
        dependent: "Dependente",
        dependent_gender: "M",
        dependents: "Dependentes",
        user: "Usuário",
        user_gender: "M",
        users: "Usuários",
    },
    theme: {
        mode: "system",
        preset: "default",
        primaryColor: "#0284c7",
        secondaryColor: "#0369a1",
        backgroundColor: "#f0f9ff",
        surfaceColor: "#ffffff",
        textColor: "#0c4a6e",
        textSecondaryColor: "#475569",
        borderColor: "#7dd3fc",
    },
};

// Default label definitions
const defaultLabels = {
    entity: "Cliente",
    entity_gender: "M",
    entities: "Clientes",
    agreement: "Contrato",
    agreement_gender: "M",
    agreements: "Contratos",
    category: "Categoria",
    category_gender: "F",
    categories: "Categorias",
    subcategory: "Subcategoria",
    subcategory_gender: "F",
    subcategories: "Subcategorias",
    dependent: "Dependente",
    dependent_gender: "M",
    dependents: "Dependentes",
    user: "Usuário",
    user_gender: "M",
    users: "Usuários",
};

// Default accessibility preferences
const defaultAccessibility = {
    highContrast: false,
    colorBlindMode: "none",
};

export const ConfigProvider = ({ children }) => {
    const [config, setConfig] = useState(defaultSettings);
    const [loading, setLoading] = useState(true);

    // User theme settings from API
    const [userThemeSettings, setUserThemeSettings] = useState(null);
    const [canEditTheme, setCanEditTheme] = useState(false);
    const [themePermissions, setThemePermissions] = useState({
        usersCanEditTheme: false,
        adminsCanEditTheme: true,
    });
    const [themeSaving, setThemeSaving] = useState(false);

    // Theme mode and accessibility preferences
    const [themeMode, setThemeModeState] = useState("system");
    const [accessibility, setAccessibilityState] =
        useState(defaultAccessibility);

    // Resolved theme mode (light/dark)
    const [resolvedMode, setResolvedMode] = useState("light");

    // Fetch system settings from API
    const fetchSettings = useCallback(async () => {
        const token = localStorage.getItem("accessToken");
        if (!token) {
            setLoading(false);
            return;
        }
        try {
            const res = await fetch("/api/settings", {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });
            if (!res.ok) throw new Error("Fetch settings error");

            const data = await res.json();

            const newConfig = { ...defaultSettings };

            // Handle both map (object) and array responses
            const settingsToProcess = Array.isArray(data)
                ? data
                : Object.entries(data).map(([key, value]) => ({ key, value }));

            for (const item of settingsToProcess) {
                const parts = item.key.split(".");
                let obj = newConfig;

                for (let i = 0; i < parts.length - 1; i++) {
                    let val = parts[i];
                    if (!obj[val]) obj[val] = {};
                    obj = obj[val];
                }
                obj[parts[parts.length - 1]] = item.value;
            }

            setConfig(newConfig);
        } catch (err) {
            console.error("Error fetching settings:", err);
        } finally {
            setLoading(false);
        }
    }, []);

    // Fetch user theme settings from API
    const fetchUserTheme = useCallback(async () => {
        const token = localStorage.getItem("accessToken");
        if (!token) {
            // Fall back to localStorage if not logged in
            const savedMode = localStorage.getItem("themeMode");
            const savedAccessibility = localStorage.getItem("accessibility");
            if (savedMode) setThemeModeState(savedMode);
            if (savedAccessibility) {
                try {
                    setAccessibilityState(JSON.parse(savedAccessibility));
                } catch (e) {
                    console.error("Error parsing saved accessibility:", e);
                }
            }
            return;
        }

        try {
            const response = await themeApi.getUserTheme("/api", token, () => {
                // Token expired - fall back to localStorage
                const savedMode = localStorage.getItem("themeMode");
                if (savedMode) setThemeModeState(savedMode);
            });

            // Set permissions
            setCanEditTheme(response.can_edit || false);
            if (response.permissions) {
                setThemePermissions({
                    usersCanEditTheme:
                        response.permissions.users_can_edit_theme || false,
                    adminsCanEditTheme:
                        response.permissions.admins_can_edit_theme || true,
                });
            }

            // Set user theme settings
            if (response.settings) {
                const settings = themeApi.apiToFrontend(response.settings);
                setUserThemeSettings(settings);
                setThemeModeState(settings.mode || "system");
                setAccessibilityState({
                    highContrast: settings.highContrast || false,
                    colorBlindMode: settings.colorBlindMode || "none",
                });

                // Update config theme if user has custom settings
                // Use explicit check for preset to avoid falsy string issues
                setConfig((prev) => {
                    const newPreset =
                        settings.preset && settings.preset !== ""
                            ? settings.preset
                            : prev.theme.preset;
                    return {
                        ...prev,
                        theme: {
                            ...prev.theme,
                            preset: newPreset,
                            primaryColor:
                                settings.primaryColor ||
                                prev.theme.primaryColor,
                            secondaryColor:
                                settings.secondaryColor ||
                                prev.theme.secondaryColor,
                            backgroundColor:
                                settings.backgroundColor ||
                                prev.theme.backgroundColor,
                            surfaceColor:
                                settings.surfaceColor ||
                                prev.theme.surfaceColor,
                            textColor:
                                settings.textColor || prev.theme.textColor,
                            textSecondaryColor:
                                settings.textSecondaryColor ||
                                prev.theme.textSecondaryColor,
                            borderColor:
                                settings.borderColor || prev.theme.borderColor,
                        },
                    };
                });
            } else {
                // No user settings - use localStorage as fallback
                const savedMode = localStorage.getItem("themeMode");
                const savedAccessibility =
                    localStorage.getItem("accessibility");
                if (savedMode) setThemeModeState(savedMode);
                if (savedAccessibility) {
                    try {
                        setAccessibilityState(JSON.parse(savedAccessibility));
                    } catch (e) {
                        console.error("Error parsing saved accessibility:", e);
                    }
                }
            }
        } catch (err) {
            console.error("Error fetching user theme:", err);
            // Fall back to localStorage
            const savedMode = localStorage.getItem("themeMode");
            const savedAccessibility = localStorage.getItem("accessibility");
            if (savedMode) setThemeModeState(savedMode);
            if (savedAccessibility) {
                try {
                    setAccessibilityState(JSON.parse(savedAccessibility));
                } catch (e) {
                    console.error("Error parsing saved accessibility:", e);
                }
            }
        }
    }, []);

    // Save user theme settings to API
    const saveUserTheme = useCallback(
        async (themeSettings) => {
            const token = localStorage.getItem("accessToken");
            if (!token || !canEditTheme) {
                // Save to localStorage if not logged in or no permission
                if (themeSettings.mode) {
                    localStorage.setItem("themeMode", themeSettings.mode);
                }
                if (
                    themeSettings.highContrast !== undefined ||
                    themeSettings.colorBlindMode !== undefined
                ) {
                    localStorage.setItem(
                        "accessibility",
                        JSON.stringify({
                            highContrast: themeSettings.highContrast || false,
                            colorBlindMode:
                                themeSettings.colorBlindMode || "none",
                        }),
                    );
                }
                return;
            }

            setThemeSaving(true);
            try {
                const apiSettings = themeApi.frontendToApi(themeSettings);
                await themeApi.updateUserTheme(
                    "/api",
                    token,
                    apiSettings,
                    () => {
                        console.error("Token expired while saving theme");
                    },
                );
                setUserThemeSettings(themeSettings);
            } catch (err) {
                console.error("Error saving user theme:", err);
                // Fall back to localStorage on error
                if (themeSettings.mode) {
                    localStorage.setItem("themeMode", themeSettings.mode);
                }
                throw err;
            } finally {
                setThemeSaving(false);
            }
        },
        [canEditTheme],
    );

    // Initial fetch
    useEffect(() => {
        fetchSettings();
        fetchUserTheme();
    }, [fetchSettings, fetchUserTheme]);

    // Update theme mode
    const setThemeMode = useCallback(
        async (mode) => {
            setThemeModeState(mode);
            localStorage.setItem("themeMode", mode); // Always save locally for immediate effect

            // Try to save to API if possible
            const token = localStorage.getItem("accessToken");
            if (token && canEditTheme) {
                try {
                    const currentSettings = userThemeSettings || {
                        preset: config.theme?.preset || "default",
                        mode: mode,
                        primaryColor: config.theme?.primaryColor,
                        secondaryColor: config.theme?.secondaryColor,
                        backgroundColor: config.theme?.backgroundColor,
                        surfaceColor: config.theme?.surfaceColor,
                        textColor: config.theme?.textColor,
                        textSecondaryColor: config.theme?.textSecondaryColor,
                        borderColor: config.theme?.borderColor,
                        highContrast: accessibility.highContrast,
                        colorBlindMode: accessibility.colorBlindMode,
                        focusIndicator: accessibility.focusIndicator,
                    };
                    await saveUserTheme({ ...currentSettings, mode });
                } catch (err) {
                    console.error("Error saving theme mode:", err);
                }
            }
        },
        [
            canEditTheme,
            userThemeSettings,
            config.theme,
            accessibility,
            saveUserTheme,
        ],
    );

    // Update accessibility settings
    const setAccessibility = useCallback(
        async (prefs) => {
            const newPrefs = { ...accessibility, ...prefs };
            setAccessibilityState(newPrefs);
            localStorage.setItem("accessibility", JSON.stringify(newPrefs)); // Always save locally

            // Try to save to API if possible
            const token = localStorage.getItem("accessToken");
            if (token && canEditTheme) {
                try {
                    const currentSettings = userThemeSettings || {
                        preset: config.theme?.preset || "default",
                        mode: themeMode,
                        primaryColor: config.theme?.primaryColor,
                        secondaryColor: config.theme?.secondaryColor,
                        backgroundColor: config.theme?.backgroundColor,
                        surfaceColor: config.theme?.surfaceColor,
                        textColor: config.theme?.textColor,
                        textSecondaryColor: config.theme?.textSecondaryColor,
                        borderColor: config.theme?.borderColor,
                        highContrast: newPrefs.highContrast,
                        colorBlindMode: newPrefs.colorBlindMode,
                    };
                    await saveUserTheme({
                        ...currentSettings,
                        highContrast: newPrefs.highContrast,
                        colorBlindMode: newPrefs.colorBlindMode,
                    });
                } catch (err) {
                    console.error("Error saving accessibility settings:", err);
                }
            }
        },
        [
            accessibility,
            canEditTheme,
            userThemeSettings,
            config.theme,
            themeMode,
            saveUserTheme,
        ],
    );

    // Check system theme preference
    const checkSystemTheme = () => {
        const prefersDark = window.matchMedia(
            "(prefers-color-scheme: dark)",
        ).matches;
        return prefersDark ? "dark" : "light";
    };

    const updateResolvedMode = useCallback(() => {
        if (themeMode === "system") {
            setResolvedMode(checkSystemTheme());
        } else {
            setResolvedMode(themeMode);
        }
    }, [themeMode]);

    // Listen for system theme changes
    useEffect(() => {
        updateResolvedMode();
        const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
        const handler = (e) => {
            if (themeMode === "system") {
                setResolvedMode(e.matches ? "dark" : "light");
            }
        };
        mediaQuery.addEventListener("change", handler);
        return () => mediaQuery.removeEventListener("change", handler);
    }, [themeMode, updateResolvedMode]);

    // Apply theme colors to CSS variables
    useEffect(() => {
        updateResolvedMode();
        const root = document.documentElement;

        const preset = config?.theme?.preset || "default";
        const primaryColor = config?.theme?.primaryColor;
        const secondaryColor = config?.theme?.secondaryColor;
        const backgroundColor = config?.theme?.backgroundColor;
        const surfaceColor = config?.theme?.surfaceColor;
        const textColor = config?.theme?.textColor;
        const textSecondaryColor = config?.theme?.textSecondaryColor;
        const borderColor = config?.theme?.borderColor;

        let themeColors;

        // Check for accessibility overrides first
        if (
            accessibility.colorBlindMode &&
            accessibility.colorBlindMode !== "none"
        ) {
            const colorblindPalette =
                COLORBLIND_SAFE[accessibility.colorBlindMode];
            themeColors =
                resolvedMode === "dark"
                    ? colorblindPalette.dark
                    : colorblindPalette.light;
        } else if (preset === "custom") {
            // Custom theme - create distinct light/dark variants from custom colors
            const customLight = {
                buttonPrimary: primaryColor || "#0284c7",
                buttonSecondary: secondaryColor || "#0369a1",
                bgPage: backgroundColor || "#f0f9ff",
                bgCard: surfaceColor || "#ffffff",
                textPrimary: textColor || "#0c4a6e",
                textSecondary: textSecondaryColor || "#475569",
                borderDefault: borderColor || "#7dd3fc",
            };

            // Create a properly contrasted dark variant
            const customDark = {
                buttonPrimary: lightenColor(primaryColor || "#0284c7", 15),
                buttonSecondary: lightenColor(secondaryColor || "#0369a1", 10),
                bgPage: darkenColor(backgroundColor || "#f0f9ff", 85),
                bgCard: darkenColor(surfaceColor || "#ffffff", 75),
                textPrimary: "#e0f2fe",
                textSecondary: "#94a3b8",
                borderDefault: darkenColor(borderColor || "#7dd3fc", 40),
            };
            themeColors = resolvedMode === "dark" ? customDark : customLight;
        } else if (preset && THEME_PRESETS[preset]) {
            // Preset theme
            themeColors =
                resolvedMode === "dark"
                    ? THEME_PRESETS[preset].dark
                    : THEME_PRESETS[preset].light;
        } else {
            // Fallback to default
            themeColors =
                resolvedMode === "dark"
                    ? THEME_PRESETS.default.dark
                    : THEME_PRESETS.default.light;
        }
        // Helper to get brightness (simplified)
        const getBrightness = (hex) => {
            if (!hex) return 0;
            const c = hex.replace("#", "");
            if (c.length !== 6) return 0;
            const rgb = parseInt(c, 16);
            const r = (rgb >> 16) & 0xff;
            const g = (rgb >> 8) & 0xff;
            const b = (rgb >> 0) & 0xff;
            return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };

        // Determine text colors based on background brightness
        let primaryTextColor = "#ffffff";
        if (
            themeColors.buttonPrimary &&
            getBrightness(themeColors.buttonPrimary) > 150
        ) {
            primaryTextColor = "#000000";
        }

        let secondaryTextColor = "#ffffff";
        if (
            themeColors.buttonSecondary &&
            getBrightness(themeColors.buttonSecondary) > 150
        ) {
            secondaryTextColor = "#000000";
        }

        // Apply Mode Class
        if (resolvedMode === "dark") {
            root.classList.add("dark-mode");
            root.classList.remove("light-mode");
        } else {
            root.classList.add("light-mode");
            root.classList.remove("dark-mode");
        }

        // Safety check - ensure themeColors is defined
        if (!themeColors) {
            console.error("Theme colors not defined, using default");
            themeColors = THEME_PRESETS.default.light;
        }

        // Apply CSS variables (matching project's existing CSS variable names)
        root.style.setProperty(
            "--primary-color",
            themeColors.buttonPrimary || "#0284c7",
        );
        root.style.setProperty(
            "--secondary-color",
            themeColors.buttonSecondary || "#0369a1",
        );
        root.style.setProperty("--bg-color", themeColors.bgPage || "#f0f9ff");
        root.style.setProperty("--content-bg", themeColors.bgCard || "#ffffff");
        root.style.setProperty(
            "--text-color",
            themeColors.textPrimary || "#0c4a6e",
        );
        root.style.setProperty(
            "--text-secondary-color",
            themeColors.textSecondary || "#475569",
        );
        root.style.setProperty(
            "--border-color",
            themeColors.borderDefault || "#7dd3fc",
        );
        root.style.setProperty("--primary-text-color", primaryTextColor);
        root.style.setProperty("--secondary-text-color", secondaryTextColor);

        // Apply nav text color (falls back to secondaryTextColor if not defined)
        root.style.setProperty(
            "--nav-text-color",
            themeColors.textNav || secondaryTextColor,
        );

        // Apply app background color (falls back to secondary color if not defined)
        root.style.setProperty(
            "--app-bg-color",
            themeColors.bgNavbar || themeColors.buttonSecondary || "#0369a1",
        );

        // Apply page title color (falls back to text color if not defined)
        root.style.setProperty(
            "--page-title-color",
            themeColors.textTitle || themeColors.textPrimary || "#0369a1",
        );

        // Apply active nav text color (falls back to primaryTextColor if not defined)
        root.style.setProperty(
            "--active-nav-text-color",
            themeColors.textNavActive || primaryTextColor,
        );

        // Generate hover colors
        root.style.setProperty(
            "--primary-dark",
            darkenColor(themeColors.buttonPrimary, 10),
        );
        root.style.setProperty(
            "--secondary-light",
            darkenColor(themeColors.buttonSecondary, 10),
        );
    }, [config, resolvedMode, themeMode, accessibility, updateResolvedMode]);

    // Apply accessibility classes and attributes
    useEffect(() => {
        const root = document.documentElement;

        // High contrast filter
        if (accessibility.highContrast) {
            root.classList.add("high-contrast-filter");
        } else {
            root.classList.remove("high-contrast-filter");
        }

        // Color blind mode
        if (
            accessibility.colorBlindMode &&
            accessibility.colorBlindMode !== "none"
        ) {
            root.classList.add(`colorblind-${accessibility.colorBlindMode}`);
        } else {
            // Remove all colorblind classes
            root.classList.remove(
                "colorblind-protanopia",
                "colorblind-deuteranopia",
                "colorblind-tritanopia",
            );
        }
    }, [accessibility]);

    // Helper function to darken a color
    function darkenColor(hex, percent) {
        if (!hex) return hex;
        const c = hex.replace("#", "");
        if (c.length !== 6) return hex;
        const num = parseInt(c, 16);
        const amt = Math.round(2.55 * percent);
        let r = (num >> 16) - amt;
        let g = ((num >> 8) & 0x00ff) - amt;
        let b = (num & 0x0000ff) - amt;
        r = Math.max(0, r);
        g = Math.max(0, g);
        b = Math.max(0, b);
        return (
            "#" +
            (
                0x1000000 +
                (r < 255 ? (r < 1 ? 0 : r) : 255) * 0x10000 +
                (g < 255 ? (g < 1 ? 0 : g) : 255) * 0x100 +
                (b < 255 ? (b < 1 ? 0 : b) : 255)
            )
                .toString(16)
                .slice(1)
        );
    }

    // Helper function to lighten a color
    function lightenColor(hex, percent) {
        if (!hex) return hex;
        const c = hex.replace("#", "");
        if (c.length !== 6) return hex;
        const num = parseInt(c, 16);
        const amt = Math.round(2.55 * percent);
        let r = (num >> 16) + amt;
        let g = ((num >> 8) & 0x00ff) + amt;
        let b = (num & 0x0000ff) + amt;
        r = Math.min(255, r);
        g = Math.min(255, g);
        b = Math.min(255, b);
        return (
            "#" +
            (
                0x1000000 +
                (r < 255 ? (r < 1 ? 0 : r) : 255) * 0x10000 +
                (g < 255 ? (g < 1 ? 0 : g) : 255) * 0x100 +
                (b < 255 ? (b < 1 ? 0 : b) : 255)
            )
                .toString(16)
                .slice(1)
        );
    }

    // Update system settings (branding, labels, global theme)
    const updateSettings = async (newSettings) => {
        // Update local state
        setConfig((prev) => ({
            ...prev,
            ...newSettings,
        }));

        // If theme settings are being updated, also save user theme
        if (newSettings.theme && canEditTheme) {
            try {
                const themeSettings = {
                    preset:
                        newSettings.theme.preset ||
                        config.theme?.preset ||
                        "default",
                    mode: themeMode,
                    primaryColor: newSettings.theme.primaryColor || null,
                    secondaryColor: newSettings.theme.secondaryColor || null,
                    backgroundColor: newSettings.theme.backgroundColor || null,
                    surfaceColor: newSettings.theme.surfaceColor || null,
                    textColor: newSettings.theme.textColor || null,
                    textSecondaryColor:
                        newSettings.theme.textSecondaryColor || null,
                    borderColor: newSettings.theme.borderColor || null,
                    highContrast: accessibility.highContrast,
                    colorBlindMode: accessibility.colorBlindMode,
                    focusIndicator: accessibility.focusIndicator,
                };
                await saveUserTheme(themeSettings);
            } catch (err) {
                console.error("Error saving user theme:", err);
            }
        }

        // Convert nested settings to flat key-value pairs for system settings
        const flatSettings = {};
        const flattenObject = (obj, prefix = "") => {
            for (const key in obj) {
                const fullKey = prefix ? `${prefix}.${key}` : key;
                if (
                    typeof obj[key] === "object" &&
                    obj[key] !== null &&
                    !Array.isArray(obj[key])
                ) {
                    flattenObject(obj[key], fullKey);
                } else {
                    // Backend espera map[string]string, então convertemos valor para string
                    const value = obj[key];
                    flatSettings[fullKey] =
                        value === null || value === undefined
                            ? ""
                            : String(value);
                }
            }
        };

        // Only flatten non-theme settings for system settings API
        const systemSettings = { ...newSettings };
        delete systemSettings.theme; // Theme is handled separately per user
        flattenObject(systemSettings);

        // Save to API (system settings)
        const token = localStorage.getItem("accessToken");
        if (!token) return;

        try {
            const res = await fetch("/api/settings", {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ settings: flatSettings }),
            });

            // Recarrega as configurações após salvar com sucesso
            if (res.ok) {
                await fetchSettings();
            }
            if (!res.ok) throw new Error("Failed to save settings");
        } catch (err) {
            console.error("Error saving settings:", err);
        }
    };

    // Save only theme settings to user API
    const saveThemeSettings = useCallback(
        async (themeData) => {
            if (!canEditTheme) {
                console.warn("User does not have permission to edit theme");
                return;
            }

            const themeSettings = {
                preset: themeData.preset || config.theme?.preset || "default",
                mode: themeData.mode || themeMode,
                primaryColor: themeData.primaryColor || null,
                secondaryColor: themeData.secondaryColor || null,
                backgroundColor: themeData.backgroundColor || null,
                surfaceColor: themeData.surfaceColor || null,
                textColor: themeData.textColor || null,
                textSecondaryColor: themeData.textSecondaryColor || null,
                borderColor: themeData.borderColor || null,
                highContrast:
                    themeData.highContrast !== undefined
                        ? themeData.highContrast
                        : accessibility.highContrast,
                colorBlindMode:
                    themeData.colorBlindMode || accessibility.colorBlindMode,
            };

            try {
                await saveUserTheme(themeSettings);

                // Update local config
                setConfig((prev) => ({
                    ...prev,
                    theme: {
                        ...prev.theme,
                        preset: themeSettings.preset,
                        primaryColor: themeSettings.primaryColor,
                        secondaryColor: themeSettings.secondaryColor,
                        backgroundColor: themeSettings.backgroundColor,
                        surfaceColor: themeSettings.surfaceColor,
                        textColor: themeSettings.textColor,
                        textSecondaryColor: themeSettings.textSecondaryColor,
                        borderColor: themeSettings.borderColor,
                    },
                }));

                if (themeSettings.mode && themeSettings.mode !== themeMode) {
                    setThemeModeState(themeSettings.mode);
                }

                if (
                    themeSettings.highContrast !== accessibility.highContrast ||
                    themeSettings.colorBlindMode !==
                        accessibility.colorBlindMode
                ) {
                    setAccessibilityState({
                        highContrast: themeSettings.highContrast,
                        colorBlindMode: themeSettings.colorBlindMode,
                    });
                }
            } catch (err) {
                console.error("Error saving theme settings:", err);
                throw err;
            }
        },
        [canEditTheme, config.theme, themeMode, accessibility, saveUserTheme],
    );

    // Persistent filter state
    const getPersistentFilter = (key) => {
        try {
            const saved = localStorage.getItem(`filter_${key}`);
            return saved ? JSON.parse(saved) : null;
        } catch {
            return null;
        }
    };

    const setPersistentFilter = (key, value) => {
        try {
            localStorage.setItem(`filter_${key}`, JSON.stringify(value));
        } catch (err) {
            console.error("Error saving filter:", err);
        }
    };

    // Helper to get label with fallback
    const getLabel = (key) => {
        const value = config?.labels?.[key] || defaultLabels[key] || key;
        return value;
    };

    // Helper to get gender-specific text
    const getGenderHelpers = (key) => {
        let gender = config?.labels?.[`${key}_gender`] || "M";

        // Singular label
        const value = getLabel(key);

        if (gender === "M") {
            return {
                label: value,
                article: "o",
                articleUpper: "O",
                new: "Novo",
                none: "Nenhum",
                found: "Encontrado",
                all: "Todos",
                active: "Ativo",
                inactive: "Inativo",
                archived: "Arquivado",
            };
        } else if (gender === "F") {
            return {
                label: value,
                article: "a",
                articleUpper: "A",
                new: "Nova",
                none: "Nenhuma",
                found: "Encontrada",
                all: "Todas",
                active: "Ativa",
                inactive: "Inativa",
                archived: "Arquivada",
            };
        } else {
            return {
                label: value,
                article: gender === "N" ? "@" : "x",
                articleUpper: gender === "N" ? "@" : "X",
                new: gender === "N" ? "Nov@" : "Novx",
                none: gender === "N" ? "Nenhum@" : "Nenhunx",
                found: gender === "N" ? "Encontrad@" : "Encontradx",
                all: gender === "N" ? "Tod@s" : "Todxs",
                active: gender === "N" ? "Ativ@" : "Ativx",
                inactive: gender === "N" ? "Inativ@" : "Inativx",
                archived: gender === "N" ? "Arquivad@" : "Arquivadx",
            };
        }
    };

    // Create config with fallbacks for all label properties
    const configWithFallbacks = {
        ...config,
        labels: {
            ...Object.keys(defaultLabels).reduce((acc, key) => {
                const value = config?.labels?.[key] || defaultLabels[key];
                acc[key] = value;
                return acc;
            }, {}),
        },
    };

    const value = {
        config: configWithFallbacks,
        loading,
        updateSettings,
        themeMode,
        setThemeMode,
        resolvedMode,
        accessibility,
        setAccessibility,
        getPersistentFilter,
        setPersistentFilter,
        getLabel,
        getGenderHelpers,
        fetchSettings,
        // New theme-related exports
        canEditTheme,
        themePermissions,
        themeSaving,
        saveThemeSettings,
        fetchUserTheme,
        userThemeSettings,
    };

    return (
        <ConfigContext.Provider value={value}>
            {children}
        </ConfigContext.Provider>
    );
};

export default ConfigProvider;
