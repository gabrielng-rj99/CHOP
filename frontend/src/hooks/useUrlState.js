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

import { useState, useEffect, useCallback, useRef } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Hook customizado para gerenciar estado na URL (Query Params).
 * Ótimo para filtros, paginação e buscas que devem persistir ao recarregar a página.
 *
 * @param {Object} initialState - Estado inicial padrão (ex: { page: 1, filter: 'all' })
 * @param {Object} config - Configurações opcionais
 * @param {boolean} config.debounce - Se deve aplicar debounce (para buscas)
 * @param {number} config.debounceTime - Tempo de debounce em ms (padrão 500)
 * @returns {Object} { values, updateValue, updateValues, reset }
 */
export function useUrlState(initialState, config = {}) {
    const { debounce = false, debounceTime = 500, syncWithUrl = true } = config;
    const [searchParams, setSearchParams] = useSearchParams();

    // Converte SearchParams para objeto
    const getValuesFromUrl = useCallback(() => {
        const values = { ...initialState };
        let hasParam = false;

        // Se a URL estiver vazia, retorna inicial.
        // Mas se tiver params, tentamos ler.
        for (const key of Object.keys(initialState)) {
            const paramVal = searchParams.get(key);
            if (paramVal !== null) {
                values[key] = paramVal;
                hasParam = true;
            }
        }
        return values;
    }, [searchParams, initialState]);

    const [localState, setLocalState] = useState(
        syncWithUrl ? getValuesFromUrl() : initialState,
    );
    const debounceTimeout = useRef(null);

    // Sincroniza estado local se a URL mudar externamente (ex: botão voltar), apenas se syncWithUrl
    useEffect(() => {
        if (!syncWithUrl) return;
        const currentUrlValues = getValuesFromUrl();
        if (JSON.stringify(currentUrlValues) !== JSON.stringify(localState)) {
            setLocalState(currentUrlValues);
        }
    }, [searchParams]);

    // Sempre sincronizar a URL com o estado local atual, apenas se syncWithUrl
    useEffect(() => {
        if (!syncWithUrl) return;
        applyToUrl(localState);
    }, [localState]);

    const applyToUrl = (newState) => {
        if (!syncWithUrl) return;
        setSearchParams(
            (prev) => {
                const newParams = new URLSearchParams(prev);
                Object.entries(newState).forEach(([key, value]) => {
                    if (value !== "" && value !== undefined && value !== null) {
                        newParams.set(key, value);
                    } else {
                        newParams.delete(key);
                    }
                });
                return newParams;
            },
            { replace: debounce },
        ); // Se for debounce (busca), usa replace pra não sujar histórico
    };

    const updateValue = (key, value) => {
        const newState = { ...localState, [key]: value };
        setLocalState(newState);

        if (debounce) {
            if (debounceTimeout.current) clearTimeout(debounceTimeout.current);
            debounceTimeout.current = setTimeout(() => {
                applyToUrl(newState);
            }, debounceTime);
        } else {
            applyToUrl(newState);
        }
    };

    // Atualiza múltiplos valores de uma vez
    const updateValues = (newValues) => {
        const newState = { ...localState, ...newValues };
        setLocalState(newState);
        if (debounce) {
            if (debounceTimeout.current) clearTimeout(debounceTimeout.current);
            debounceTimeout.current = setTimeout(() => {
                applyToUrl(newState);
            }, debounceTime);
        } else {
            applyToUrl(newState);
        }
    };

    // Atualiza múltiplos valores IMEDIATAMENTE (sem debounce)
    // Útil para filtros e paginação que devem reagir instantaneamente
    const updateValuesImmediate = (newValues) => {
        if (debounceTimeout.current) clearTimeout(debounceTimeout.current);
        const newState = { ...localState, ...newValues };
        setLocalState(newState);
        applyToUrl(newState);
    };

    return {
        values: localState,
        updateValue,
        updateValues,
        updateValuesImmediate,
        setSearchParams, // escape hatch
    };
}
