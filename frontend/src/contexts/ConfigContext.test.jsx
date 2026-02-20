// @vitest-environment jsdom
import { render, screen, act, waitFor, cleanup } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { ConfigProvider, useConfig } from "./ConfigContext";
import { themeApi } from "../api/themeApi.js";

vi.mock("../api/themeApi.js", () => ({
    themeApi: {
        getUserTheme: vi.fn().mockResolvedValue({
            can_edit: false,
            permissions: {
                users_can_edit_theme: false,
                admins_can_edit_theme: true,
            },
            allowed_themes: [],
            global_theme: null,
            settings: null,
        }),
        apiToFrontend: vi.fn((value) => value),
        frontendToApi: vi.fn((value) => value),
        updateUserTheme: vi.fn().mockResolvedValue({}),
    },
}));

let latestContext = null;

const TestHarness = () => {
    const ctx = useConfig();
    latestContext = ctx;
    return (
        <div>
            <div data-testid="app-name">{ctx.config.branding.appName}</div>
            <div data-testid="primary-color">
                {ctx.config.theme.primaryColor}
            </div>
        </div>
    );
};

const mockMatchMedia = (matches = false) => {
    const listeners = new Set();
    Object.defineProperty(window, "matchMedia", {
        writable: true,
        value: vi.fn().mockImplementation((query) => ({
            matches,
            media: query,
            addEventListener: (_event, cb) => listeners.add(cb),
            removeEventListener: (_event, cb) => listeners.delete(cb),
            addListener: (cb) => listeners.add(cb),
            removeListener: (cb) => listeners.delete(cb),
            dispatchEvent: (event) => {
                listeners.forEach((cb) => cb(event));
                return true;
            },
        })),
    });
};

describe("ConfigContext", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({}),
        });
        localStorage.clear();
        document.documentElement.style.cssText = "";
        document.documentElement.className = "";
        mockMatchMedia(false);
    });

    afterEach(() => {
        cleanup();
    });

    it("loads default settings and labels", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        expect(screen.getByTestId("app-name").textContent).toBe("Client Hub");
        expect(screen.getByTestId("primary-color").textContent).toBe("#0284c7");

        const gender = latestContext.getGenderHelpers("client");
        expect(gender.label).toBe("Cliente");
        expect(gender.article).toBe("o");
        expect(gender.new).toBe("Novo");
    });

    it("hydrates theme from localStorage if present", async () => {
        localStorage.setItem(
            "userTheme",
            JSON.stringify({
                preset: "custom",
                primaryColor: "#111111",
                secondaryColor: "#222222",
            }),
        );

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(screen.getByTestId("primary-color").textContent).toBe(
                "#111111",
            );
        });
    });

    it("fetches settings from API on mount when token exists", async () => {
        const mockSettings = {
            "branding.appName": "API App",
            "theme.primaryColor": "#ff0000",
            "labels.client": "Cliente X",
        };

        global.fetch = vi.fn().mockResolvedValueOnce({
            ok: true,
            json: async () => mockSettings,
        });

        localStorage.setItem("accessToken", "test-token");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(screen.getByTestId("app-name").textContent).toBe("API App");
        });

        expect(global.fetch).toHaveBeenCalledWith("/api/settings", {
            headers: {
                Authorization: "Bearer test-token",
            },
        });

        expect(latestContext.config.labels.client).toBe("Cliente X");
    });

    it("setThemeMode updates localStorage and resolved mode", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.setThemeMode("dark");
        });

        await waitFor(() => {
            expect(latestContext.resolvedMode).toBe("dark");
        });

        expect(localStorage.getItem("themeMode")).toBe("dark");
        expect(document.documentElement.classList.contains("dark-mode")).toBe(
            true,
        );
    });

    it("setLayoutMode validates and applies layout classes", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.setLayoutMode("centralized");
        });

        expect(localStorage.getItem("layoutMode")).toBe("centralized");
        expect(
            document.documentElement.classList.contains("layout-centralized"),
        ).toBe(true);
    });

    it("setFonts updates storage and state", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.setFonts({ general: "Roboto" });
        });

        expect(localStorage.getItem("fontSettings")).toContain("Roboto");
        expect(latestContext.fontSettings.general).toBe("Roboto");
    });

    it("setAccessibility persists preferences and applies colorblind class", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.setAccessibility({
                colorBlindMode: "protanopia",
            });
        });

        expect(localStorage.getItem("accessibility")).toContain("protanopia");
        expect(
            document.documentElement.classList.contains(
                "colorblind-protanopia",
            ),
        ).toBe(true);
    });

    it("saveThemeSettings calls theme API when permitted", async () => {
        themeApi.getUserTheme.mockResolvedValueOnce({
            can_edit: true,
            permissions: {
                users_can_edit_theme: true,
                admins_can_edit_theme: true,
            },
            allowed_themes: [],
            global_theme: null,
            settings: {
                preset: "default",
                mode: "system",
                layoutMode: "standard",
            },
        });

        localStorage.setItem("accessToken", "token");
        localStorage.setItem("userRole", "root");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(themeApi.getUserTheme).toHaveBeenCalled();
        });

        await act(async () => {
            await latestContext.saveThemeSettings({
                preset: "custom",
                primaryColor: "#123456",
            });
        });

        expect(themeApi.updateUserTheme).toHaveBeenCalled();
    });

    it("updateSettings saves system settings via API", async () => {
        const fetchMock = vi
            .fn()
            .mockResolvedValueOnce({ ok: true, json: async () => ({}) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({}) });

        global.fetch = fetchMock;
        localStorage.setItem("accessToken", "test-token");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.updateSettings({
                branding: { appName: "Updated App" },
            });
        });

        const putCall = fetchMock.mock.calls.find(
            ([url, options]) =>
                url === "/api/settings" && options?.method === "PUT",
        );
        expect(putCall).toBeTruthy();
    });

    it("persistent filters read/write to localStorage", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            latestContext.setPersistentFilter("clients", { q: "abc" });
        });

        const restored = latestContext.getPersistentFilter("clients");
        expect(restored).toEqual({ q: "abc" });
    });

    it("falls back to localStorage for user theme when no token", async () => {
        localStorage.setItem("themeMode", "dark");
        localStorage.setItem("layoutMode", "full");
        localStorage.setItem(
            "fontSettings",
            JSON.stringify({
                general: "Lato",
                title: "Lato",
                tableTitle: "Lato",
                tableContent: "Lato",
            }),
        );
        localStorage.setItem(
            "accessibility",
            JSON.stringify({
                highContrast: true,
                colorBlindMode: "deuteranopia",
                dyslexicFont: true,
            }),
        );

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(latestContext.themeMode).toBe("dark");
        });

        expect(latestContext.layoutMode).toBe("full");
        expect(latestContext.fontSettings.general).toBe("Lato");
        expect(latestContext.accessibility.highContrast).toBe(true);
        expect(latestContext.accessibility.colorBlindMode).toBe("deuteranopia");
        expect(latestContext.accessibility.dyslexicFont).toBe(true);
    });

    it("saveUserTheme stores preferences locally when not authenticated", async () => {
        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.saveUserTheme({
                mode: "dark",
                layoutMode: "full",
                highContrast: true,
                colorBlindMode: "tritanopia",
                dyslexicFont: true,
            });
        });

        expect(localStorage.getItem("themeMode")).toBe("dark");
        expect(localStorage.getItem("layoutMode")).toBe("full");
        expect(localStorage.getItem("accessibility")).toContain("tritanopia");
    });

    it("handles settings fetch errors without blocking load", async () => {
        const errorSpy = vi
            .spyOn(console, "error")
            .mockImplementation(() => {});
        localStorage.setItem("accessToken", "test-token");
        global.fetch = vi.fn().mockRejectedValueOnce(new Error("boom"));

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(latestContext.loading).toBe(false);
        });

        expect(errorSpy).toHaveBeenCalled();
        errorSpy.mockRestore();
    });

    it("loads user theme settings and updates config", async () => {
        themeApi.getUserTheme.mockResolvedValueOnce({
            can_edit: true,
            permissions: {
                users_can_edit_theme: true,
                admins_can_edit_theme: true,
            },
            allowed_themes: ["default"],
            global_theme: { preset: "default" },
            settings: {
                preset: "custom",
                mode: "light",
                layoutMode: "standard",
                primaryColor: "#445566",
                secondaryColor: "#667788",
                backgroundColor: "#f0f0f0",
                surfaceColor: "#ffffff",
                textColor: "#111111",
                textSecondaryColor: "#222222",
                borderColor: "#333333",
                fontGeneral: "Inter",
                fontTitle: "Inter",
                fontTableTitle: "Inter",
                fontTableContent: "Inter",
                highContrast: false,
                colorBlindMode: "none",
                dyslexicFont: false,
            },
        });

        localStorage.setItem("accessToken", "token");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(latestContext.userThemeSettings).toBeTruthy();
            expect(latestContext.config.theme.primaryColor).toBe("#445566");
        });

        expect(latestContext.themeMode).toBe("light");
        expect(latestContext.allowedThemes).toEqual(["default"]);
        expect(latestContext.globalTheme).toEqual({ preset: "default" });
    });

    it("saveThemePermissions hits API and updates context", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({}),
        });

        global.fetch = fetchMock;
        localStorage.setItem("accessToken", "token");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(latestContext.loading).toBe(false);
        });

        await act(async () => {
            await latestContext.saveThemePermissions(true, false);
        });

        const putCall = fetchMock.mock.calls.find(
            ([url, options]) =>
                url === "/api/settings/theme-permissions" &&
                options?.method === "PUT",
        );
        expect(putCall).toBeTruthy();
        await waitFor(() => {
            expect(latestContext.themePermissions).toEqual({
                usersCanEditTheme: true,
                adminsCanEditTheme: false,
            });
        });
    });

    it("saveGlobalTheme calls API with payload", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({}),
        });

        global.fetch = fetchMock;
        localStorage.setItem("accessToken", "token");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await act(async () => {
            await latestContext.saveGlobalTheme({
                preset: "custom",
                primaryColor: "#000000",
            });
        });

        const putCall = fetchMock.mock.calls.find(
            ([url, options]) =>
                url === "/api/settings/global-theme" &&
                options?.method === "PUT",
        );
        expect(putCall).toBeTruthy();
    });

    it("saveThemeSettings skips when user lacks permission", async () => {
        themeApi.getUserTheme.mockResolvedValueOnce({
            can_edit: false,
            permissions: {
                users_can_edit_theme: false,
                admins_can_edit_theme: false,
            },
            allowed_themes: [],
            global_theme: null,
            settings: null,
        });

        localStorage.setItem("accessToken", "token");
        localStorage.setItem("userRole", "user");

        render(
            <ConfigProvider>
                <TestHarness />
            </ConfigProvider>,
        );

        await waitFor(() => {
            expect(themeApi.getUserTheme).toHaveBeenCalled();
        });

        await act(async () => {
            await latestContext.saveThemeSettings({
                preset: "custom",
                primaryColor: "#abcdef",
            });
        });

        expect(themeApi.updateUserTheme).not.toHaveBeenCalled();
    });
});
