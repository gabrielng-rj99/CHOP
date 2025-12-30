#!/usr/bin/env node

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

const fs = require('fs');
const path = require('path');

// Mapeamento de nomes antigos para novos
const RENAME_MAP = {
    'primary': 'buttonPrimary',
    'secondary': 'buttonSecondary',
    'background': 'bgPage',
    'surface': 'bgCard',
    'text': 'textPrimary',
    'textSecondary': 'textSecondary', // mantém o mesmo
    'border': 'borderDefault',
    'navText': 'textNav',
    'appBg': 'bgNavbar',
    'pageTitle': 'textTitle',
    'activeNavText': 'textNavActive'
};

const THEMES_DIR = path.join(__dirname, '../frontend/src/contexts/themes');

function renamePropertiesInObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    if (Array.isArray(obj)) {
        return obj.map(renamePropertiesInObject);
    }

    const newObj = {};
    for (const [key, value] of Object.entries(obj)) {
        const newKey = RENAME_MAP[key] || key;
        newObj[newKey] = renamePropertiesInObject(value);
    }
    return newObj;
}

function processThemeFile(filePath) {
    console.log(`Processing: ${filePath}`);

    let content = fs.readFileSync(filePath, 'utf8');

    // Substituir as chaves dos objetos mantendo a estrutura
    // Procura por padrões como "primary:" ou "primary: "
    for (const [oldName, newName] of Object.entries(RENAME_MAP)) {
        if (oldName === newName) continue;

        // Substitui as propriedades nos objetos mantendo indentação
        const regex = new RegExp(`(\\s+)${oldName}:`, 'g');
        content = content.replace(regex, `$1${newName}:`);
    }

    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`✓ Updated: ${filePath}`);
}

function main() {
    console.log('Starting theme variable renaming...\n');

    // Processar todos os arquivos .js na pasta themes
    const files = fs.readdirSync(THEMES_DIR);

    files.forEach(file => {
        if (file.endsWith('.js')) {
            const filePath = path.join(THEMES_DIR, file);
            processThemeFile(filePath);
        }
    });

    console.log('\n✓ All theme files updated successfully!');
    console.log('\nNext steps:');
    console.log('1. Update ConfigContext.jsx to use new property names');
    console.log('2. Test the application to ensure themes work correctly');
}

main();
