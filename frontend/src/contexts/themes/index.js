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

// Import all theme groups
import { defaultTheme } from "./default.js";
import { blueThemes } from "./01-blue.js";
import { cyanThemes } from "./02-cyan.js";
import { greenThemes } from "./03-green.js";
import { yellowGreenThemes } from "./04-yellow-green.js";
import { yellowThemes } from "./05-yellow.js";
import { yellowOrangeThemes } from "./06-yellow-orange.js";
import { orangeThemes } from "./07-orange.js";
import { redOrangeThemes } from "./08-red-orange.js";
import { redThemes } from "./09-red.js";
import { redPurpleThemes } from "./10-red-purple.js";
import { purpleThemes } from "./11-purple.js";
import { bluePurpleThemes } from "./12-blue-purple.js";
import { bonusThemes } from "./bonus.js";

// Combine all themes ordered by color wheel position starting with Blue
// Ordered: Azul → Ciano → Verde → Amarelo Esverdeado → Amarelo → Amarelo Alaranjado →
//          Laranja → Laranja Avermelhado → Vermelho → Roxo Avermelhado → Roxo → Roxo Azulado → Especiais
export const THEME_PRESETS = {
    // Default Theme
    ...defaultTheme,

    // 1. AZUL (Blue) - Position 1 on Color Wheel
    ...blueThemes,

    // 2. CYAN - Position 2 on Color Wheel
    ...cyanThemes,

    // 3. VERDE (Green) - Position 3 on Color Wheel
    ...greenThemes,

    // 4. AMARELO ESVERDEADO (Yellow-Green) - Position 4 on Color Wheel
    ...yellowGreenThemes,

    // 5. AMARELO (Yellow) - Position 5 on Color Wheel
    ...yellowThemes,

    // 6. AMARELO ALARANJADO (Yellow-Orange) - Position 6 on Color Wheel
    ...yellowOrangeThemes,

    // 7. LARANJA (Orange) - Position 7 on Color Wheel
    ...orangeThemes,

    // 8. LARANJA AVERMELHADO (Red-Orange) - Position 8 on Color Wheel
    ...redOrangeThemes,

    // 9. VERMELHO (Red) - Position 9 on Color Wheel
    ...redThemes,

    // 10. ROXO AVERMELHADO (Red-Purple) - Position 10 on Color Wheel
    ...redPurpleThemes,

    // 11. ROXO (Purple) - Position 11 on Color Wheel
    ...purpleThemes,

    // 12. ROXO AZULADO (Blue-Purple) - Position 12 on Color Wheel
    ...bluePurpleThemes,

    // BONUS: Complementary and Special Themes
    ...bonusThemes,
};

// Export individual groups for direct access if needed
export {
    defaultTheme,
    blueThemes,
    cyanThemes,
    greenThemes,
    yellowGreenThemes,
    yellowThemes,
    yellowOrangeThemes,
    orangeThemes,
    redOrangeThemes,
    redThemes,
    redPurpleThemes,
    purpleThemes,
    bluePurpleThemes,
    bonusThemes,
};

// Total count: 55 themes
// - 1 Default (Tema Padrão)
// - 48 Color Wheel Themes (12 positions × 4 themes each)
// - 6 Bonus Themes (Complementary color schemes)
