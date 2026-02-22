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

/**
 * Shared API error handling utilities.
 *
 * Provides consistent detection and messaging for common HTTP error statuses
 * across all API modules (401 Unauthorized, 429 Too Many Requests, etc.).
 */

/**
 * Checks the response for common HTTP error statuses and throws
 * descriptive, user-facing errors when appropriate.
 *
 * Must be called **before** any `!response.ok` generic check so that
 * specific statuses (401, 429) get their own clear messages instead of
 * falling through to a generic "Falha ao carregar" style error.
 *
 * @param {Response} response - The Fetch API Response object
 * @param {function} [onTokenExpired] - Optional callback invoked when token is expired/invalid (401)
 * @returns {Response} The same response object (pass-through for chaining)
 * @throws {Error} With a user-facing message for 401 or 429 statuses
 *
 * @example
 *   const response = await fetch(url, options);
 *   handleResponseErrors(response, onTokenExpired);
 *   if (!response.ok) {
 *       throw new Error("Erro ao carregar dados");
 *   }
 *   return await response.json();
 */
export function handleResponseErrors(response, onTokenExpired) {
    if (response.status === 401) {
        onTokenExpired?.();
        throw new Error(
            "Token inválido ou expirado. Faça login novamente.",
        );
    }

    if (response.status === 429) {
        throw new Error(
            "Excesso de requisições na API. Aguarde um momento e tente novamente.",
        );
    }

    return response;
}

/**
 * Convenience wrapper: checks common errors **and** throws a generic
 * fallback error when `!response.ok` (any other non-2xx status).
 *
 * Use this when the caller does NOT need to inspect the response body
 * for a server-provided error message — i.e. the simple/common case.
 *
 * @param {Response} response - The Fetch API Response object
 * @param {string} fallbackMessage - Message used when the status is not 401/429 but still not ok
 * @param {function} [onTokenExpired] - Optional callback for 401
 * @returns {Response} The same response object
 * @throws {Error}
 *
 * @example
 *   const response = await fetch(url, options);
 *   await assertResponseOk(response, "Erro ao carregar clientes", onTokenExpired);
 *   return await response.json();
 */
export async function assertResponseOk(
    response,
    fallbackMessage,
    onTokenExpired,
) {
    handleResponseErrors(response, onTokenExpired);

    if (!response.ok) {
        // Try to extract a server-provided error message
        let serverMessage = null;
        try {
            const body = await response.clone().json();
            serverMessage = body?.error || null;
        } catch {
            // Response body is not JSON or is empty — ignore
        }
        throw new Error(serverMessage || fallbackMessage);
    }

    return response;
}
