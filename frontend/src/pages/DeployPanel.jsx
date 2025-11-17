import React, { useState, useEffect } from 'react';
import './DeployPanel.css';

const DeployPanel = () => {
  const [config, setConfig] = useState({
    serverHost: 'localhost',
    serverPort: '3000',
    databaseHost: 'localhost',
    databasePort: '5432',
    databaseName: 'contracts_manager',
    databaseUser: 'postgres',
    databasePassword: '',
    databaseSSLMode: 'disable',
    jwtSecretKey: '',
    jwtExpirationTime: 60,
    jwtRefreshExpirationTime: 10080,
    securityPasswordMinLength: 8,
    securityMaxFailedAttempts: 5,
    securityLockoutDurationMinutes: 30,
    appEnv: 'development',
  });

  const [deployToken, setDeployToken] = useState('');
  const [status, setStatus] = useState(null);
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [currentStatus, setCurrentStatus] = useState(null);
  const [showSecrets, setShowSecrets] = useState(false);

  // Fetch current configuration status
  useEffect(() => {
    fetchConfigStatus();
  }, []);

  const fetchConfigStatus = async () => {
    try {
      const response = await fetch('/api/deploy/status');
      if (response.ok) {
        const data = await response.json();
        setCurrentStatus(data);
      }
    } catch (error) {
      console.error('Error fetching config status:', error);
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig({
      ...config,
      [name]: type === 'checkbox' ? checked : value,
    });
    setErrors([]);
  };

  const validateConfig = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/deploy/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(deployToken && { Authorization: `Bearer ${deployToken}` }),
        },
        body: JSON.stringify(config),
      });

      const data = await response.json();
      if (!data.success) {
        setErrors(data.errors || ['Validation failed']);
        return false;
      }
      return true;
    } catch (error) {
      setErrors([`Validation error: ${error.message}`]);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const handleDeploy = async (e) => {
    e.preventDefault();
    setErrors([]);

    // Validate before deploying
    const isValid = await validateConfig();
    if (!isValid) {
      return;
    }

    try {
      setLoading(true);
      const response = await fetch('/api/deploy/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(deployToken && { Authorization: `Bearer ${deployToken}` }),
        },
        body: JSON.stringify(config),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setStatus({
          type: 'success',
          message: 'Configuration deployed successfully!',
          config: data.config,
        });
        // Refresh status
        setTimeout(() => fetchConfigStatus(), 1000);
      } else {
        setErrors(data.errors || ['Deployment failed']);
        setStatus({
          type: 'error',
          message: 'Failed to deploy configuration',
        });
      }
    } catch (error) {
      setErrors([`Deployment error: ${error.message}`]);
      setStatus({
        type: 'error',
        message: `Error: ${error.message}`,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setConfig({
      serverHost: 'localhost',
      serverPort: '3000',
      databaseHost: 'localhost',
      databasePort: '5432',
      databaseName: 'contracts_manager',
      databaseUser: 'postgres',
      databasePassword: '',
      databaseSSLMode: 'disable',
      jwtSecretKey: '',
      jwtExpirationTime: 60,
      jwtRefreshExpirationTime: 10080,
      securityPasswordMinLength: 8,
      securityMaxFailedAttempts: 5,
      securityLockoutDurationMinutes: 30,
      appEnv: 'development',
    });
    setErrors([]);
    setStatus(null);
  };

  const generateSecureSecret = () => {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let secret = '';
    for (let i = 0; i < 32; i++) {
      secret += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setConfig({ ...config, jwtSecretKey: secret });
  };

  return (
    <div className="deploy-panel">
      <div className="deploy-header">
        <h1>🚀 Deployment Configuration Panel</h1>
        <p>Configure and deploy application settings at runtime</p>
      </div>

      {currentStatus && (
        <div className="status-box">
          <div className="status-item">
            <strong>Status:</strong> <span className="status-running">{currentStatus.status}</span>
          </div>
          <div className="status-item">
            <strong>Environment:</strong> <span>{currentStatus.environment}</span>
          </div>
          <div className="status-item">
            <strong>Version:</strong> <span>{currentStatus.version}</span>
          </div>
          <div className="status-item">
            <strong>Database:</strong> <span>{currentStatus.db_host}:{currentStatus.db_name}</span>
          </div>
          {currentStatus.secrets_status && (
            <div className="status-item">
              <strong>Secrets Status:</strong>
              <div className="secrets-status">
                {Object.entries(currentStatus.secrets_status).map(([key, value]) => (
                  <div key={key} className="secret-status">
                    <span className="secret-name">{key}:</span>
                    <span className={`secret-value ${value.includes('set') ? 'set' : 'not-set'}`}>
                      {value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {status && (
        <div className={`status-alert ${status.type}`}>
          <strong>{status.type === 'success' ? '✅' : '❌'}</strong>
          <span>{status.message}</span>
        </div>
      )}

      {errors.length > 0 && (
        <div className="error-alert">
          <strong>⚠️ Errors:</strong>
          <ul>
            {errors.map((error, idx) => (
              <li key={idx}>{error}</li>
            ))}
          </ul>
        </div>
      )}

      <form onSubmit={handleDeploy} className="deploy-form">
        <div className="form-section">
          <h3>📡 Server Configuration</h3>
          <div className="form-group">
            <label htmlFor="serverHost">Server Host</label>
            <input
              type="text"
              id="serverHost"
              name="serverHost"
              value={config.serverHost}
              onChange={handleInputChange}
              placeholder="localhost"
            />
          </div>
          <div className="form-group">
            <label htmlFor="serverPort">Server Port</label>
            <input
              type="text"
              id="serverPort"
              name="serverPort"
              value={config.serverPort}
              onChange={handleInputChange}
              placeholder="3000"
            />
          </div>
        </div>

        <div className="form-section">
          <h3>🗄️ Database Configuration</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="databaseHost">Host</label>
              <input
                type="text"
                id="databaseHost"
                name="databaseHost"
                value={config.databaseHost}
                onChange={handleInputChange}
                placeholder="localhost"
              />
            </div>
            <div className="form-group">
              <label htmlFor="databasePort">Port</label>
              <input
                type="text"
                id="databasePort"
                name="databasePort"
                value={config.databasePort}
                onChange={handleInputChange}
                placeholder="5432"
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="databaseName">Database Name</label>
              <input
                type="text"
                id="databaseName"
                name="databaseName"
                value={config.databaseName}
                onChange={handleInputChange}
                placeholder="contracts_manager"
              />
            </div>
            <div className="form-group">
              <label htmlFor="databaseUser">User</label>
              <input
                type="text"
                id="databaseUser"
                name="databaseUser"
                value={config.databaseUser}
                onChange={handleInputChange}
                placeholder="postgres"
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="databasePassword">
              Password
              <button
                type="button"
                className="toggle-secret"
                onClick={() => setShowSecrets(!showSecrets)}
              >
                {showSecrets ? '🙈' : '👁️'}
              </button>
            </label>
            <input
              type={showSecrets ? 'text' : 'password'}
              id="databasePassword"
              name="databasePassword"
              value={config.databasePassword}
              onChange={handleInputChange}
              placeholder="Enter database password"
            />
          </div>

          <div className="form-group">
            <label htmlFor="databaseSSLMode">SSL Mode</label>
            <select
              id="databaseSSLMode"
              name="databaseSSLMode"
              value={config.databaseSSLMode}
              onChange={handleInputChange}
            >
              <option value="disable">Disable</option>
              <option value="require">Require</option>
              <option value="verify-ca">Verify CA</option>
              <option value="verify-full">Verify Full</option>
            </select>
          </div>
        </div>

        <div className="form-section">
          <h3>🔐 JWT & Security</h3>
          <div className="form-group">
            <label htmlFor="jwtSecretKey">
              JWT Secret Key
              <button
                type="button"
                className="generate-btn"
                onClick={generateSecureSecret}
              >
                🔄 Generate
              </button>
            </label>
            <input
              type={showSecrets ? 'text' : 'password'}
              id="jwtSecretKey"
              name="jwtSecretKey"
              value={config.jwtSecretKey}
              onChange={handleInputChange}
              placeholder="Enter or generate a secure JWT secret"
            />
            <small>Minimum 32 characters recommended</small>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="jwtExpirationTime">JWT Expiration (minutes)</label>
              <input
                type="number"
                id="jwtExpirationTime"
                name="jwtExpirationTime"
                value={config.jwtExpirationTime}
                onChange={handleInputChange}
                min="1"
              />
            </div>
            <div className="form-group">
              <label htmlFor="jwtRefreshExpirationTime">Refresh Expiration (minutes)</label>
              <input
                type="number"
                id="jwtRefreshExpirationTime"
                name="jwtRefreshExpirationTime"
                value={config.jwtRefreshExpirationTime}
                onChange={handleInputChange}
                min="1"
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="securityPasswordMinLength">Password Min Length</label>
              <input
                type="number"
                id="securityPasswordMinLength"
                name="securityPasswordMinLength"
                value={config.securityPasswordMinLength}
                onChange={handleInputChange}
                min="6"
              />
            </div>
            <div className="form-group">
              <label htmlFor="securityMaxFailedAttempts">Max Failed Attempts</label>
              <input
                type="number"
                id="securityMaxFailedAttempts"
                name="securityMaxFailedAttempts"
                value={config.securityMaxFailedAttempts}
                onChange={handleInputChange}
                min="1"
              />
            </div>
            <div className="form-group">
              <label htmlFor="securityLockoutDurationMinutes">Lockout Duration (minutes)</label>
              <input
                type="number"
                id="securityLockoutDurationMinutes"
                name="securityLockoutDurationMinutes"
                value={config.securityLockoutDurationMinutes}
                onChange={handleInputChange}
                min="1"
              />
            </div>
          </div>
        </div>

        <div className="form-section">
          <h3>🌍 Application</h3>
          <div className="form-group">
            <label htmlFor="appEnv">Environment</label>
            <select
              id="appEnv"
              name="appEnv"
              value={config.appEnv}
              onChange={handleInputChange}
            >
              <option value="development">Development</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </div>
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleReset}
            disabled={loading}
          >
            🔄 Reset
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? '⏳ Deploying...' : '🚀 Deploy Configuration'}
          </button>
        </div>
      </form>

      <div className="deploy-notes">
        <h3>ℹ️ Important Notes</h3>
        <ul>
          <li>
            <strong>Secrets Management:</strong> This panel is for configuring secrets during
            deployment. Secrets are stored in memory and not persisted to disk.
          </li>
          <li>
            <strong>Development Mode:</strong> In development, you can deploy without
            authentication. In production, you must provide a valid deploy token.
          </li>
          <li>
            <strong>Environment Variables:</strong> Secrets set here will override environment
            variables for the current session only.
          </li>
          <li>
            <strong>Database Connection:</strong> After changing database settings, the application
            may need to reconnect. Monitor application health afterwards.
          </li>
          <li>
            <strong>JWT Secret:</strong> Use the Generate button to create a cryptographically
            secure JWT secret key.
          </li>
        </ul>
      </div>
    </div>
  );
};

export default DeployPanel;
