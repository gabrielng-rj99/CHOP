import React from "react";
import { useConfig } from "../../contexts/ConfigContext";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useNavigate, useLocation } from "react-router-dom";
import {
    faChartLine,
    faFileContract,
    faUserGroup,
    faTags,
    faUserGear,
    faSearchPlus,
    faCog,
    faPalette,
    faRightFromBracket,
} from "@fortawesome/free-solid-svg-icons";
import "./Sidebar.css";

// We can move styles here or keep using App.css if classes match.
// Assuming we keep App.css classes for now.

const Sidebar = ({ sidebarCollapsed, toggleSidebar, user, logout }) => {
    const { config } = useConfig();
    const { branding, labels } = config;
    const navigate = useNavigate();
    const location = useLocation();

    // Normalize pathname to determine active page
    // e.g. /dashboard -> dashboard
    const currentPath = location.pathname.substring(1) || "dashboard";

    return (
        <nav className={`app-nav ${sidebarCollapsed ? "collapsed" : ""}`}>
            {/* Branding Section - ACIMA (Above) the header/toggle */}
            {branding.useCustomLogo && (
                <div className="app-nav-branding">
                    {sidebarCollapsed ? (
                        /* Collapsed State - Fixed 40x40 container */
                        <div className="sidebar-logo-collapsed">
                            {branding.logoSquareUrl ? (
                                <img src={branding.logoSquareUrl} alt="Icon" />
                            ) : (
                                <div className="sidebar-logo-placeholder" />
                            )}
                        </div>
                    ) : (
                        /* Expanded State - Fixed 180x50 container to ensure no layout shift */
                        <div className="sidebar-logo-expanded">
                            {branding.logoWideUrl ? (
                                <img src={branding.logoWideUrl} alt="Logo" />
                            ) : (
                                <div className="sidebar-logo-placeholder" />
                            )}
                        </div>
                    )}
                </div>
            )}

            <div className="app-nav-header">
                <h2
                    className={`app-nav-title${sidebarCollapsed ? " hidden-title" : ""}`}
                >
                    {branding.appName || "Entity Hub"}
                </h2>
                <button onClick={toggleSidebar} className="app-nav-toggle">
                    {sidebarCollapsed ? "☰" : "←"}
                </button>
            </div>

            <div className="app-nav-items">
                <button
                    onClick={() => navigate("/dashboard")}
                    className={`app-nav-button ${currentPath === "dashboard" ? "active" : ""}`}
                    title="Dashboard"
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faChartLine} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">Dashboard</span>
                    )}
                </button>

                <button
                    onClick={() => navigate("/agreements")}
                    className={`app-nav-button ${currentPath === "agreements" ? "active" : ""}`}
                    title={labels.agreements || "Acordos"}
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faFileContract} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">
                            {labels.agreements || "Contratos"}
                        </span>
                    )}
                </button>

                <button
                    onClick={() => navigate("/clients")}
                    className={`app-nav-button ${currentPath === "clients" ? "active" : ""}`}
                    title={labels.entities || "Clientes"}
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faUserGroup} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">
                            {labels.entities || "Clientes"}
                        </span>
                    )}
                </button>

                <button
                    onClick={() => navigate("/categories")}
                    className={`app-nav-button ${currentPath === "categories" ? "active" : ""}`}
                    title={labels?.categories || "Categorias"}
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faTags} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">
                            {labels?.categories || "Categorias"}
                        </span>
                    )}
                </button>

                {(user.role === "admin" || user.role === "root") && (
                    <button
                        onClick={() => navigate("/users")}
                        className={`app-nav-button ${currentPath === "users" ? "active" : ""}`}
                        title={labels?.users || "Usuários"}
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faUserGear} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">
                                {labels?.users || "Usuários"}
                            </span>
                        )}
                    </button>
                )}

                {user.role === "root" && (
                    <button
                        onClick={() => navigate("/audit-logs")}
                        className={`app-nav-button ${currentPath === "audit-logs" ? "active" : ""}`}
                        title="Logs"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faSearchPlus} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Logs</span>
                        )}
                    </button>
                )}

                <button
                    onClick={() => navigate("/appearance")}
                    className={`app-nav-button ${currentPath === "appearance" ? "active" : ""}`}
                    title="Aparência"
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faPalette} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">Aparência</span>
                    )}
                </button>

                {(user.role === "admin" || user.role === "root") && (
                    <button
                        onClick={() => navigate("/settings")}
                        className={`app-nav-button ${currentPath === "settings" ? "active" : ""}`}
                        title="Configurações"
                    >
                        <span className="app-nav-icon">
                            <FontAwesomeIcon icon={faCog} />
                        </span>
                        {!sidebarCollapsed && (
                            <span className="app-nav-text">Configurações</span>
                        )}
                    </button>
                )}
            </div>

            <div className="app-nav-footer">
                {!sidebarCollapsed && (
                    <div className="app-nav-user-info">
                        <div className="app-nav-user-label">Usuário:</div>
                        <div className="user-name">{user.username}</div>
                        <div className="user-role">{user.role}</div>
                    </div>
                )}
                <button
                    onClick={logout}
                    className="app-nav-logout-button"
                    title="Sair"
                >
                    <span className="app-nav-icon">
                        <FontAwesomeIcon icon={faRightFromBracket} />
                    </span>
                    {!sidebarCollapsed && (
                        <span className="app-nav-text">Sair</span>
                    )}
                </button>
            </div>
        </nav>
    );
};

export default Sidebar;
