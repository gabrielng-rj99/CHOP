/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
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

import { useState, useEffect, useCallback } from "react";

export function useLastUpdate() {
    const [lastUpdate, setLastUpdate] = useState(null);
    const [relativeTime, setRelativeTime] = useState("");

    const formatRelativeTime = useCallback((date) => {
        if (!date) return "";

        const now = new Date();
        const diff = Math.floor((now - date) / 1000); // difference in seconds

        if (diff < 60) {
            return "há alguns segundos";
        } else if (diff < 3600) {
            const minutes = Math.floor(diff / 60);
            return `há ${minutes} minuto${minutes > 1 ? "s" : ""}`;
        } else if (diff < 86400) {
            const hours = Math.floor(diff / 3600);
            return `há ${hours} hora${hours > 1 ? "s" : ""}`;
        } else if (diff < 604800) {
            const days = Math.floor(diff / 86400);
            return `há ${days} dia${days > 1 ? "s" : ""}`;
        } else {
            const weeks = Math.floor(diff / 604800);
            return `há ${weeks} semana${weeks > 1 ? "s" : ""}`;
        }
    }, []);

    // Update relative time every 30 seconds
    useEffect(() => {
        if (!lastUpdate) return;

        const updateRelativeTime = () => {
            setRelativeTime(formatRelativeTime(lastUpdate));
        };

        updateRelativeTime();
        const interval = setInterval(updateRelativeTime, 30000);

        return () => clearInterval(interval);
    }, [lastUpdate, formatRelativeTime]);

    const recordUpdate = useCallback(() => {
        const now = new Date();
        setLastUpdate(now);
        setRelativeTime(formatRelativeTime(now));
    }, [formatRelativeTime]);

    return {
        lastUpdate,
        relativeTime,
        recordUpdate,
    };
}
