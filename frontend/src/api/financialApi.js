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

import { handleResponseErrors } from "./apiHelpers";

export const financialApi = {
    // ============================================
    // CONTRACT FINANCIAL
    // ============================================

    /**
     * Lista todos os financeiro
     */
    loadFinancial: async (apiUrl, token, onTokenExpired, params = {}) => {
        const url = new URL(`${apiUrl}/financial`, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== "") {
                url.searchParams.append(key, value);
            }
        });

        const response = await fetch(url.toString(), {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar financeiro");
        }

        const data = await response.json();
        // Return full response when using server-side pagination (has total/limit/offset)
        if (data.total !== undefined) {
            return data;
        }
        // Backward compatibility: return just the array for legacy callers
        return data.data || [];
    },

    /**
     * Obtém o financeiro de um contrato específico
     */
    getContractFinancial: async (apiUrl, token, contractId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/contracts/${contractId}/financial`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar financeiro do contrato");
        }

        const data = await response.json();
        return data.data; // Pode ser null se não existir
    },

    /**
     * Obtém um financeiro pelo ID
     */
    getFinancialById: async (apiUrl, token, financialId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial/${financialId}`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar financeiro");
        }

        const data = await response.json();
        return data.data;
    },

    /**
     * Cria um novo modelo de financeiro para um contrato
     * @param {Object} financialData - Dados do financeiro
     * @param {string} financialData.contract_id - ID do contrato
     * @param {string} financialData.financial_type - 'unico', 'recorrente', 'personalizado'
     * @param {string} [financialData.recurrence_type] - 'mensal', 'trimestral', 'semestral', 'anual'
     * @param {number} [financialData.due_day] - Dia do vencimento (1-31)
     * @param {number} [financialData.client_value] - Valor que o cliente paga
     * @param {number} [financialData.received_value] - Valor que você recebe
     * @param {string} [financialData.description] - Descrição
     * @param {Array} [financialData.installments] - Parcelas (para tipo personalizado)
     */
    createFinancial: async (apiUrl, token, financialData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(financialData),
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar financeiro");
        }

        return response.json();
    },

    /**
     * Atualiza um financeiro existente
     */
    updateFinancial: async (
        apiUrl,
        token,
        financialId,
        financialData,
        onTokenExpired,
    ) => {
        const response = await fetch(`${apiUrl}/financial/${financialId}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(financialData),
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar financeiro");
        }

        return response.json();
    },

    /**
     * Deleta um financeiro
     */
    deleteFinancial: async (apiUrl, token, financialId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial/${financialId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao deletar financeiro");
        }

        return response.json();
    },

    // ============================================
    // INSTALLMENTS (PARCELAS)
    // ============================================

    /**
     * Lista parcelas de um financeiro
     */
    getInstallments: async (apiUrl, token, financialId, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar parcelas");
        }

        const data = await response.json();
        return data.data || [];
    },

    /**
     * Cria uma nova parcela
     */
    createInstallment: async (
        apiUrl,
        token,
        financialId,
        installmentData,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(installmentData),
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar parcela");
        }

        return response.json();
    },

    /**
     * Atualiza uma parcela
     */
    updateInstallment: async (
        apiUrl,
        token,
        financialId,
        installmentId,
        installmentData,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments/${installmentId}`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(installmentData),
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar parcela");
        }

        return response.json();
    },

    /**
     * Marca uma parcela como paga
     */
    markInstallmentPaid: async (
        apiUrl,
        token,
        financialId,
        installmentId,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments/${installmentId}/pay`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao marcar parcela como paga");
        }

        return response.json();
    },

    /**
     * Marca uma parcela como pendente (desfaz financeiro)
     */
    markInstallmentPending: async (
        apiUrl,
        token,
        financialId,
        installmentId,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments/${installmentId}/unpay`,
            {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao marcar parcela como pendente");
        }

        return response.json();
    },

    /**
     * Deleta uma parcela
     */
    deleteInstallment: async (
        apiUrl,
        token,
        financialId,
        installmentId,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/${financialId}/installments/${installmentId}`,
            {
                method: "DELETE",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao deletar parcela");
        }

        return response.json();
    },

    // ============================================
    // DASHBOARD / SUMMARY
    // ============================================

    /**
     * Obtém resumo detalhado de financeiro com dados por período
     * Retorna: mês passado, mês atual, próximo mês, totais e breakdown mensal
     */
    getDetailedSummary: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial/detailed-summary`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar resumo detalhado de financeiro");
        }

        const data = await response.json();
        return data.data;
    },

    /**
     * Obtém resumo geral de financeiro
     */
    getFinancialSummary: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial/summary`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar resumo de financeiro");
        }

        const data = await response.json();
        return data.data;
    },

    /**
     * Obtém resumo de financeiro de um mês específico
     */
    getMonthlySummary: async (apiUrl, token, year, month, onTokenExpired) => {
        const response = await fetch(
            `${apiUrl}/financial/summary?year=${year}&month=${month}`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar resumo mensal");
        }

        const data = await response.json();
        return data.data;
    },

    /**
     * Obtém próximos financeiro/parcelas a vencer
     * @param {number} [daysAhead=30] - Quantos dias à frente buscar
     */
    getUpcomingFinancial: async (
        apiUrl,
        token,
        daysAhead = 30,
        onTokenExpired,
    ) => {
        const response = await fetch(
            `${apiUrl}/financial/upcoming?days=${daysAhead}`,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar próximos financeiro");
        }

        const data = await response.json();
        return data.data || [];
    },

    /**
     * Obtém parcelas em atraso
     */
    getOverdueFinancial: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/financial/overdue`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar financeiro em atraso");
        }

        const data = await response.json();
        return data.data || [];
    },

    // ============================================
    // HELPERS
    // ============================================

    /**
     * Formata valor monetário para exibição
     */
    formatCurrency: (value) => {
        if (value === null || value === undefined) return "-";
        return new Intl.NumberFormat("pt-BR", {
            style: "currency",
            currency: "BRL",
        }).format(value);
    },

    /**
     * Retorna label padrão para número de parcela
     */
    getInstallmentLabel: (number) => {
        if (number === 0) return "Entrada";
        return `${number}ª Parcela`;
    },

    /**
     * Retorna label traduzido para tipo de financeiro
     */
    getFinancialTypeLabel: (type) => {
        const labels = {
            unico: "Financeiro Único",
            recorrente: "Recorrente",
            personalizado: "Personalizado",
        };
        return labels[type] || type;
    },

    /**
     * Retorna label traduzido para tipo de recorrência
     */
    getRecurrenceTypeLabel: (type) => {
        const labels = {
            mensal: "Mensal",
            trimestral: "Trimestral",
            semestral: "Semestral",
            anual: "Anual",
        };
        return labels[type] || type;
    },

    /**
     * Retorna label e cor para status da parcela
     */
    getInstallmentStatusInfo: (status) => {
        const statusMap = {
            pendente: { label: "Pendente", color: "#f39c12" },
            pago: { label: "Pago", color: "#27ae60" },
            atrasado: { label: "Atrasado", color: "#e74c3c" },
            cancelado: { label: "Cancelado", color: "#95a5a6" },
        };
        return statusMap[status] || { label: status, color: "#95a5a6" };
    },
};
