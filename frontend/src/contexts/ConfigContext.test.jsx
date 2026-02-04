// @vitest-environment jsdom
import { render, screen, act, waitFor, cleanup } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { ConfigProvider, useConfig } from "./ConfigContext";

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

// Mock component to consume context
const TestComponent = () => {
    const { config, setConfig, updateSettings } = useConfig();
    return (
        <div>
            <div data-testid="app-name">{config.branding.appName}</div>
            <div data-testid="primary-color">{config.theme.primaryColor}</div>
            <button
                onClick={() =>
                    updateSettings({ branding: { appName: "New App" } })
                }
            >
                Update App Name
            </button>
        </div>
    );
};

describe("ConfigContext", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        global.fetch = vi.fn();
        // Reset document style
        document.documentElement.style.cssText = "";
    });

    afterEach(() => {
        cleanup();
    });

    it("loads default settings initially", async () => {
        render(
            <ConfigProvider>
                <TestComponent />
            </ConfigProvider>,
        );

        expect(screen.getByTestId("app-name").textContent).toBe("Client Hub");
        expect(screen.getByTestId("primary-color").textContent).toBe("#0284c7");
    });

    it("fetches settings from API on mount", async () => {
        const mockSettings = {
            "branding.appName": "API App",
            "theme.primaryColor": "#ff0000",
        };

        global.fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockSettings,
        });

        localStorage.setItem("accessToken", "test-token");

        render(
            <ConfigProvider>
                <TestComponent />
            </ConfigProvider>,
        );

        // Wait for effect
        await waitFor(() => {
            expect(screen.getByTestId("app-name").textContent).toBe("API App");
        });

        // Check if fetch was called
        expect(global.fetch).toHaveBeenCalledWith("/api/settings", {
            headers: {
                Authorization: "Bearer test-token",
            },
        });
    });
});
