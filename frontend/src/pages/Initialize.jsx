import React, { useState, useEffect } from "react";
import "./Initialize.css";

const Initialize = ({ onInitializationComplete }) => {
    const [step, setStep] = useState("check"); // check, db-config, secrets, deploy
    const [status, setStatus] = useState(null);
    const [errors, setErrors] = useState([]);
    const [serverInfo, setServerInfo] = useState(null);
    const [loading, setLoading] = useState(true);

    // Database configuration from config.ini defaults
    const [dbHost, setDbHost] = useState("localhost");
    const [dbPort, setDbPort] = useState("5432");
    const [dbName, setDbName] = useState("contracts_manager");
    const [dbUser, setDbUser] = useState("postgres");
    const [dbPassword, setDbPassword] = useState("CHANGE_ME");

    // Secrets with bad defaults
    const [dbPasswordSecret, setDbPasswordSecret] = useState("CHANGE_ME");
    const [jwtSecret, setJwtSecret] = useState("CHANGE_ME");

    // Password length controls
    const [dbPasswordLength, setDbPasswordLength] = useState(32);
    const [jwtSecretLength, setJwtSecretLength] = useState(64);

    const [showSecrets, setShowSecrets] = useState(false);
    const [testingConnection, setTestingConnection] = useState(false);

    const DB_PASSWORD_MIN = 8;
    const DB_PASSWORD_MAX = 128;
    const JWT_SECRET_MIN = 32;
    const JWT_SECRET_MAX = 256;

    useEffect(() => {
        checkBackendStatus();
    }, []);

    const checkBackendStatus = async () => {
        try {
            setLoading(true);
            setErrors([]);

            // Check backend health
            const healthResponse = await fetch("/health", {
                method: "GET",
            });

            if (!healthResponse.ok) {
                throw new Error("Backend is not responding");
            }

            // Check deployment status
            const deployResponse = await fetch("/api/deploy/status", {
                method: "GET",
            });

            if (!deployResponse.ok) {
                throw new Error("Cannot check deployment status");
            }

            const deployData = await deployResponse.json();
            setServerInfo(deployData);

            // Proceed to database configuration
            setTimeout(() => {
                setStep("db-config");
            }, 1000);
        } catch (error) {
            setErrors([error.message]);
            setStatus({
                type: "error",
                message: "Backend server is not running",
                advice: "Start the backend server with: cd backend && go run cmd/server/main.go",
            });
            setStep("error");
        } finally {
            setLoading(false);
        }
    };

    const testDatabaseConnection = async () => {
        try {
            setTestingConnection(true);
            setErrors([]);

            // First, initialize the database
            const initResponse = await fetch("/api/initialize/database", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    database_host: dbHost,
                    database_port: dbPort,
                    database_name: dbName,
                    database_user: dbUser,
                    database_password: dbPassword,
                }),
            });

            const initData = await initResponse.json();

            if (!initResponse.ok || !initData.success) {
                setErrors(initData.errors || ["Failed to initialize database"]);
                return;
            }

            setStatus({
                type: "success",
                message: "Database initialized! ✓",
            });

            setTimeout(() => {
                setStep("secrets");
                setStatus(null);
            }, 1000);
        } catch (error) {
            setErrors([`Database initialization failed: ${error.message}`]);
        } finally {
            setTestingConnection(false);
        }
    };

    const generateSecurePassword = (length = 32) => {
        const chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
        let password = "";
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    };

    const generateSecureSecret = (length = 64) => {
        const chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let secret = "";
        for (let i = 0; i < length; i++) {
            secret += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return secret;
    };

    const handleGenerateDbPassword = () => {
        const password = generateSecurePassword(dbPasswordLength);
        setDbPasswordSecret(password);
    };

    const handleGenerateJwtSecret = () => {
        const secret = generateSecureSecret(jwtSecretLength);
        setJwtSecret(secret);
    };

    const handleDbPasswordLengthChange = (newLength) => {
        setDbPasswordLength(newLength);
        const password = generateSecurePassword(newLength);
        setDbPasswordSecret(password);
    };

    const handleJwtSecretLengthChange = (newLength) => {
        setJwtSecretLength(newLength);
        const secret = generateSecureSecret(newLength);
        setJwtSecret(secret);
    };

    const copyToClipboard = (text) => {
        navigator.clipboard
            .writeText(text)
            .then(() => {
                alert("✓ Copied to clipboard!");
            })
            .catch(() => {
                alert("Failed to copy");
            });
    };

    const handleDeployConfiguration = async () => {
        try {
            setLoading(true);
            setErrors([]);

            // Validate secrets
            if (!dbPasswordSecret || dbPasswordSecret === "CHANGE_ME") {
                setErrors([
                    "❌ Database password not set. Please change from default!",
                ]);
                return;
            }

            if (!jwtSecret || jwtSecret === "CHANGE_ME") {
                setErrors([
                    "❌ JWT secret not set. Please change from default!",
                ]);
                return;
            }

            if (dbPasswordSecret.length < 8) {
                setErrors([
                    "❌ Database password must be at least 8 characters",
                ]);
                return;
            }

            if (jwtSecret.length < 32) {
                setErrors(["❌ JWT secret must be at least 32 characters"]);
                return;
            }

            // Deploy configuration
            const response = await fetch("/api/deploy/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    server_host: "localhost",
                    server_port: "3000",
                    database_host: dbHost,
                    database_port: dbPort,
                    database_name: dbName,
                    database_user: dbUser,
                    database_password: dbPasswordSecret,
                    jwt_secret_key: jwtSecret,
                    app_env: "development",
                }),
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                setErrors(data.errors || ["Failed to deploy configuration"]);
                return;
            }

            setStatus({
                type: "success",
                message:
                    "✅ Configuration deployed! Creating root admin user...",
            });

            // Small delay before creating admin
            await new Promise((resolve) => setTimeout(resolve, 500));

            // Now create the root admin user
            const adminResponse = await fetch("/api/initialize/admin", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: "root",
                    display_name: "Administrator",
                    password: dbPasswordSecret,
                }),
            });

            const adminData = await adminResponse.json();

            if (!adminResponse.ok || !adminData.success) {
                setErrors(
                    adminData.errors || ["Failed to create root admin user"],
                );
                return;
            }

            setStatus({
                type: "success",
                message: "✅ Root admin created! Redirecting to login...",
            });

            // Call completion callback after a delay
            setTimeout(() => {
                onInitializationComplete();
            }, 2000);
        } catch (error) {
            setErrors([`Deployment failed: ${error.message}`]);
        } finally {
            setLoading(false);
        }
    };

    const handleRetry = () => {
        setStep("check");
        setErrors([]);
        setStatus(null);
        checkBackendStatus();
    };

    // ============= RENDER SCREENS =============

    if (step === "error") {
        return (
            <div className="initialize-container">
                <div className="initialize-screen error-screen">
                    <div className="init-icon">❌</div>
                    <h1>Cannot Connect to Backend</h1>
                    <p className="init-message">{status?.message}</p>
                    <p className="init-advice">{status?.advice}</p>
                    <button
                        className="init-button primary"
                        onClick={handleRetry}
                    >
                        🔄 Retry Connection
                    </button>
                </div>
            </div>
        );
    }

    if (step === "check" || loading) {
        return (
            <div className="initialize-container">
                <div className="initialize-screen checking-screen">
                    <div className="init-spinner">⏳</div>
                    <h1>Initializing Application</h1>
                    <p>Checking backend server...</p>
                    <div className="init-progress">
                        <div className="progress-item">
                            <span className="progress-icon">✓</span>
                            <span>Backend Server</span>
                            <span
                                className={`status ${serverInfo ? "connected" : "checking"}`}
                            >
                                {serverInfo ? "Connected" : "Checking..."}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    if (step === "db-config") {
        return (
            <div className="initialize-container">
                <div className="initialize-screen db-config-screen">
                    <div className="init-icon">🗄️</div>
                    <h1>Database Configuration</h1>
                    <p className="init-message">
                        Configure your database connection details (from
                        config.ini)
                    </p>

                    {errors.length > 0 && (
                        <div className="error-alert">
                            <strong>⚠️ Error:</strong>
                            <ul>
                                {errors.map((err, idx) => (
                                    <li key={idx}>{err}</li>
                                ))}
                            </ul>
                        </div>
                    )}

                    {status && status.type === "success" && (
                        <div className="success-alert">
                            <strong>✅ {status.message}</strong>
                        </div>
                    )}

                    <div className="config-form">
                        <div className="form-section">
                            <h3>PostgreSQL Connection</h3>

                            <div className="form-row">
                                <div className="form-group">
                                    <label htmlFor="db-host">Host</label>
                                    <input
                                        id="db-host"
                                        type="text"
                                        value={dbHost}
                                        onChange={(e) =>
                                            setDbHost(e.target.value)
                                        }
                                        placeholder="localhost"
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="db-port">Port</label>
                                    <input
                                        id="db-port"
                                        type="text"
                                        value={dbPort}
                                        onChange={(e) =>
                                            setDbPort(e.target.value)
                                        }
                                        placeholder="5432"
                                    />
                                </div>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label htmlFor="db-name">
                                        Database Name
                                    </label>
                                    <input
                                        id="db-name"
                                        type="text"
                                        value={dbName}
                                        onChange={(e) =>
                                            setDbName(e.target.value)
                                        }
                                        placeholder="contracts_manager"
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="db-user">User</label>
                                    <input
                                        id="db-user"
                                        type="text"
                                        value={dbUser}
                                        onChange={(e) =>
                                            setDbUser(e.target.value)
                                        }
                                        placeholder="postgres"
                                    />
                                </div>
                            </div>

                            <div className="form-group">
                                <label htmlFor="db-password">Password</label>
                                <div className="input-with-toggle">
                                    <input
                                        id="db-password"
                                        type={showSecrets ? "text" : "password"}
                                        value={dbPassword}
                                        onChange={(e) =>
                                            setDbPassword(e.target.value)
                                        }
                                        placeholder="PostgreSQL password"
                                    />
                                    <button
                                        type="button"
                                        className="toggle-secret"
                                        onClick={() =>
                                            setShowSecrets(!showSecrets)
                                        }
                                        title="Show/hide"
                                    >
                                        {showSecrets ? "🙈" : "👁️"}
                                    </button>
                                </div>
                            </div>
                        </div>

                        <button
                            className="init-button primary"
                            onClick={testDatabaseConnection}
                            disabled={testingConnection || !dbPassword}
                        >
                            {testingConnection
                                ? "⏳ Initializing..."
                                : "🚀 Initialize Database"}
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    if (step === "secrets") {
        const isDbPasswordBad = dbPasswordSecret === "CHANGE_ME";
        const isJwtBad = jwtSecret === "CHANGE_ME";

        return (
            <div className="initialize-container">
                <div className="initialize-screen secrets-screen">
                    <div className="init-icon">🔐</div>
                    <h1>Set Application Secrets</h1>
                    <p className="init-message">
                        ⚠️ Change these from their default insecure values!
                    </p>

                    {errors.length > 0 && (
                        <div className="error-alert">
                            <strong>⚠️ Error:</strong>
                            <ul>
                                {errors.map((err, idx) => (
                                    <li key={idx}>{err}</li>
                                ))}
                            </ul>
                        </div>
                    )}

                    {status && status.type === "success" && (
                        <div className="success-alert">
                            <strong>✅ {status.message}</strong>
                        </div>
                    )}

                    <div className="secrets-form">
                        <div className="form-section">
                            <h3>🗄️ Database Password</h3>
                            <p className="warning-box">
                                <strong>
                                    ⚠️ Currently: {dbPasswordSecret}
                                </strong>
                                <br />
                                Used to authenticate with PostgreSQL. Must be
                                changed!
                            </p>

                            <div className="form-group">
                                <div className="form-header">
                                    <label htmlFor="db-password-secret">
                                        Password (Length: {dbPasswordLength})
                                    </label>
                                    <button
                                        type="button"
                                        className="toggle-secret"
                                        onClick={() =>
                                            setShowSecrets(!showSecrets)
                                        }
                                        title="Show/hide"
                                    >
                                        {showSecrets ? "🙈" : "👁️"}
                                    </button>
                                </div>

                                <div className="password-input-wrapper">
                                    <input
                                        id="db-password-secret"
                                        type={showSecrets ? "text" : "password"}
                                        value={dbPasswordSecret}
                                        onChange={(e) =>
                                            setDbPasswordSecret(e.target.value)
                                        }
                                        placeholder="Must be changed from default"
                                        className={
                                            isDbPasswordBad ? "field-error" : ""
                                        }
                                    />
                                    <button
                                        type="button"
                                        className="copy-btn"
                                        onClick={() =>
                                            copyToClipboard(dbPasswordSecret)
                                        }
                                        title="Copy to clipboard"
                                    >
                                        📋
                                    </button>
                                </div>

                                <div className="slider-container">
                                    <input
                                        type="range"
                                        min={DB_PASSWORD_MIN}
                                        max={DB_PASSWORD_MAX}
                                        value={dbPasswordLength}
                                        onChange={(e) =>
                                            handleDbPasswordLengthChange(
                                                parseInt(e.target.value),
                                            )
                                        }
                                        className="length-slider"
                                        title="Adjust password length"
                                    />
                                    <span className="slider-label">
                                        {DB_PASSWORD_MIN} - {DB_PASSWORD_MAX}
                                    </span>
                                </div>

                                <button
                                    type="button"
                                    className="generate-btn"
                                    onClick={handleGenerateDbPassword}
                                    title="Generate secure password"
                                >
                                    🔐 Generate
                                </button>

                                <small>
                                    {isDbPasswordBad ? (
                                        <span style={{ color: "red" }}>
                                            ❌ Still using default value!
                                        </span>
                                    ) : (
                                        <span style={{ color: "green" }}>
                                            ✓ Custom value set
                                        </span>
                                    )}
                                </small>
                            </div>
                        </div>

                        <div className="form-section">
                            <h3>🔑 JWT Secret Key</h3>
                            <p className="warning-box">
                                <strong>⚠️ Currently: {jwtSecret}</strong>
                                <br />
                                Used to sign JWT tokens. Must be changed!
                            </p>

                            <div className="form-group">
                                <div className="form-header">
                                    <label htmlFor="jwt-secret">
                                        Secret Key (Length: {jwtSecretLength})
                                    </label>
                                </div>

                                <div className="password-input-wrapper">
                                    <input
                                        id="jwt-secret"
                                        type={showSecrets ? "text" : "password"}
                                        value={jwtSecret}
                                        onChange={(e) =>
                                            setJwtSecret(e.target.value)
                                        }
                                        placeholder="Must be changed from default"
                                        className={
                                            isJwtBad ? "field-error" : ""
                                        }
                                    />
                                    <button
                                        type="button"
                                        className="copy-btn"
                                        onClick={() =>
                                            copyToClipboard(jwtSecret)
                                        }
                                        title="Copy to clipboard"
                                    >
                                        📋
                                    </button>
                                </div>

                                <div className="slider-container">
                                    <input
                                        type="range"
                                        min={JWT_SECRET_MIN}
                                        max={JWT_SECRET_MAX}
                                        value={jwtSecretLength}
                                        onChange={(e) =>
                                            handleJwtSecretLengthChange(
                                                parseInt(e.target.value),
                                            )
                                        }
                                        className="length-slider"
                                        title="Adjust secret length"
                                    />
                                    <span className="slider-label">
                                        {JWT_SECRET_MIN} - {JWT_SECRET_MAX}
                                    </span>
                                </div>

                                <button
                                    type="button"
                                    className="generate-btn"
                                    onClick={handleGenerateJwtSecret}
                                    title="Generate secure JWT secret"
                                >
                                    🔑 Generate
                                </button>

                                <small>
                                    {isJwtBad ? (
                                        <span style={{ color: "red" }}>
                                            ❌ Still using default value!
                                        </span>
                                    ) : (
                                        <span style={{ color: "green" }}>
                                            ✓ Custom value set
                                        </span>
                                    )}
                                </small>
                            </div>
                        </div>

                        <div className="form-section">
                            <h3>📋 Status</h3>
                            <div className="status-checklist">
                                <div className="status-item">
                                    <span
                                        className={
                                            isDbPasswordBad ? "bad" : "good"
                                        }
                                    >
                                        {isDbPasswordBad ? "❌" : "✓"}
                                    </span>
                                    <span>Database Password Changed</span>
                                </div>
                                <div className="status-item">
                                    <span className={isJwtBad ? "bad" : "good"}>
                                        {isJwtBad ? "❌" : "✓"}
                                    </span>
                                    <span>JWT Secret Changed</span>
                                </div>
                            </div>
                        </div>

                        <button
                            className="init-button primary large"
                            onClick={handleDeployConfiguration}
                            disabled={loading || isDbPasswordBad || isJwtBad}
                            title={
                                isDbPasswordBad || isJwtBad
                                    ? "Please change both secrets from defaults"
                                    : "Deploy configuration and create admin"
                            }
                        >
                            {loading
                                ? "⏳ Deploying..."
                                : "✅ Deploy & Initialize"}
                        </button>
                    </div>
                </div>
            </div>
        );
    }
};

export default Initialize;
