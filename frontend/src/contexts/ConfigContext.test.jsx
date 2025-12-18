// @vitest-environment jsdom
import { render, screen, act, waitFor, cleanup } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { ConfigProvider, useConfig } from './ConfigContext';

// Mock component to consume context
const TestComponent = () => {
    const { config, setConfig, updateSettings } = useConfig();
    return (
        <div>
            <div data-testid="app-name">{config.branding.appName}</div>
            <div data-testid="primary-color">{config.theme.primaryColor}</div>
            <button onClick={() => updateSettings({ branding: { appName: "New App" } })}>
                Update App Name
            </button>
        </div>
    );
};

describe('ConfigContext', () => {
    beforeEach(() => {
        vi.resetAllMocks();
        global.fetch = vi.fn();
        // Reset document style
        document.documentElement.style.cssText = '';
    });

    afterEach(() => {
        cleanup();
    });

    it('loads default settings initially', async () => {
        render(
            <ConfigProvider>
                <TestComponent />
            </ConfigProvider>
        );

        expect(screen.getByTestId('app-name').textContent).toBe('Entity Hub');
        expect(screen.getByTestId('primary-color').textContent).toBe('#3498db');
    });

    it('fetches settings from API on mount', async () => {
        const mockSettings = {
            "branding.appName": "API App",
            "theme.primaryColor": "#ff0000"
        };

        global.fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => mockSettings,
        });

        render(
            <ConfigProvider apiUrl="/api" token="test-token">
                <TestComponent />
            </ConfigProvider>
        );

        // Wait for effect
        await waitFor(() => {
            expect(screen.getByTestId('app-name').textContent).toBe('API App');
        });

        // Check if fetch was called
        expect(global.fetch).toHaveBeenCalledWith('/api/settings');
    });


});
