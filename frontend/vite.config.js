/*
 * This file is part of Client Hub Open Project.
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Read from environment or use defaults
const VITE_PORT = parseInt(process.env.VITE_PORT || "5173", 10);
const API_PORT = parseInt(process.env.API_PORT || "3000", 10);

export default defineConfig({
    plugins: [react()],
    server: {
        port: VITE_PORT,
        host: "0.0.0.0", // Allow external connections
        proxy: {
            "/api": {
                target: `http://localhost:${API_PORT}`,
                changeOrigin: true,
                secure: false,
                ws: true, // WebSocket support
            },
            "/uploads": {
                target: `http://localhost:${API_PORT}`,
                changeOrigin: true,
            },
        },
    },
    build: {
        outDir: "dist",
        sourcemap: true,
    },
});
