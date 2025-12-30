# Client Hub Open Project

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/github/go-mod/go-version/gabrielng-rj99/Licenses-Manager)](https://golang.org)
[![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

**Transparent Governance & Client Management for the Modern Organization.**

Client Hub is a highly secure, customizable, and audit-ready platform designed to manage complex relationships between clients, contracts, and affiliates.

---

## 🚀 Why Client Hub?

- **Security First**: Built with a "Zero Trust" mindset. Robust RBAC, JWT fingerprinting, and progressive brute-force protection.
- **Audit Ready**: Every single mutation (Create, Update, Delete, Archive) is logged with a snapshot of changes.
- **Client & Contract Focused**: Specifically designed to manage Clients, their Subsidiaries (Affiliates), and their Contracts/Licenses.
- **Highly Customizable**: Labels, categories, and theme settings allow you to tailor the platform.

## ✨ Key Features

- **Client Management**: Hierarchical management of clients, branches, and affiliates.
- **Contract Lifecycle**: Track start dates, expiration alerts, and statuses.
- **Granular RBAC**: Three-tier role system (Root, Admin, User).
- **Advanced Audit Logs**: Detailed history logs with diffs.
- **Whitelabeling**: Customize application name and branding.

---

## 📥 Getting Started

### Prerequisites

- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)

### Quick Start (Docker)

1. Clone the repository:

    ```bash
    git clone https://github.com/gabrielng-rj99/Licenses-Manager.git
    cd Licenses-Manager
    ```

2. Deploy via the Manager Script:

    ```bash
    cd deploy
    make build
    ./bin/deploy-manager
    # Select Option 10: Full Docker Stack
    ```

3. Access the web interface at `http://localhost:8081`.

---

## 📖 Documentation

All documentation is located in the `docs/` directory:

- [**API Documentation**](docs/APIs.md) - Detailed endpoint definitions.
- [**System Architecture**](docs/ARCHITECTURE.md) - Design patterns, database schema, security model (Rate Limiting, Password Policy, Caching).
- [**Deployment Guide**](deploy/README.md) - *Coming soon* (Check `deploy/` directory for scripts).

### Governance

- [**Contributing Guidelines**](docs/CONTRIBUTING.md)
- [**Security Policy**](docs/SECURITY.md)
- [**Code of Conduct**](docs/CODE_OF_CONDUCT.md)

---

## 📜 License

This project is licensed under the **GNU Affero General Public License v3.0**.

The AGPL-3.0 is a strong copyleft license designed to ensure that if you improve this software and provide it as a service (SaaS), you **must** share your improvements back with the community.

---

*Powered by the Client Hub Open Project Contributors.*
