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

import React, { useState, useRef, useEffect } from "react";
import { useConfig } from "../../contexts/ConfigContext";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faUniversalAccess } from "@fortawesome/free-solid-svg-icons";
import "./AccessibilityMenu.css";

export default function AccessibilityMenu() {
    const { accessibility, setAccessibility, resolvedMode } = useConfig();
    const [isOpen, setIsOpen] = useState(false);
    const menuRef = useRef(null);

    // Calculate position
    const [popoverStyle, setPopoverStyle] = useState({});

    useEffect(() => {
        if (isOpen && menuRef.current) {
            const rect = menuRef.current.getBoundingClientRect();
            setPopoverStyle({
                position: "fixed",
                bottom: window.innerHeight - rect.top + 10 + "px", // 10px above the button
                left: rect.left + "px",
                zIndex: 9999,
            });
        }
    }, [isOpen]);

    // Close on click outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () =>
            document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    const toggleHighContrast = () => {
        setAccessibility({ highContrast: !accessibility.highContrast });
    };

    const setColorBlindMode = (mode) => {
        setAccessibility({ colorBlindMode: mode });
    };

    const colorBlindOptions = [
        { value: "none", label: "Desativado" },
        { value: "protanopia", label: "Protanopia (vermelho)" },
        { value: "deuteranopia", label: "Deuteranopia (verde)" },
        { value: "tritanopia", label: "Tritanopia (azul)" },
    ];

    return (
        <div className="accessibility-menu-container" ref={menuRef}>
            <button
                className={`accessibility-toggle ${isOpen ? "active" : ""}`}
                onClick={() => setIsOpen(!isOpen)}
                title="Opções de Acessibilidade"
            >
                <FontAwesomeIcon icon={faUniversalAccess} />
            </button>

            {isOpen && (
                <div className="accessibility-popover" style={popoverStyle}>
                    <div className="accessibility-section">
                        <div className="accessibility-item">
                            <span className="label">Alto Contraste</span>
                            <button
                                className={`pill-toggle ${accessibility.highContrast ? "on" : "off"}`}
                                onClick={toggleHighContrast}
                            >
                                {accessibility.highContrast ? "ON" : "OFF"}
                            </button>
                        </div>
                    </div>

                    <div className="accessibility-section">
                        <div className="accessibility-label">
                            Modo Daltonismo
                        </div>
                        <div className="colorblind-options">
                            {colorBlindOptions.map((option) => (
                                <button
                                    key={option.value}
                                    className={`colorblind-option ${accessibility.colorBlindMode === option.value ? "active" : ""}`}
                                    onClick={() =>
                                        setColorBlindMode(option.value)
                                    }
                                >
                                    {option.label}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
