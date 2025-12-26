import React, { useEffect } from "react";
import { useConfig } from "../../contexts/ConfigContext";

const LayoutManager = () => {
    const { fontSettings } = useConfig();
    // Default to 'centralized' (which corresponds to 'standard' in the UI "Padrão") if not set
    const layoutMode = fontSettings?.layoutMode || "standard";

    useEffect(() => {
        const appMain = document.querySelector(".app-main");
        if (appMain) {
            // Remove all layout classes first
            appMain.classList.remove(
                "layout-mode-spacious",
                "layout-mode-full",
                "layout-mode-centralized",
            );

            // Add current layout class
            // UI uses "standard" for "Padrão" (Standard/Centralized) and "full" for "Tela Cheia"
            // "centralized" is an alias for standard in our logic if needed, but the state uses 'standard'
            appMain.classList.add(`layout-mode-${layoutMode}`);
        }
    }, [layoutMode]);

    return null;
};

export default LayoutManager;
