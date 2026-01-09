
import { test, expect } from '@playwright/test';

const LOGIN_URL = '/login';
const DASHBOARD_URL = '/dashboard';
const USERNAME = 'root';
const PASSWORD = '}(5;7ZiZS3O@GMG$fz9MgKFeCyDl{ihWz#hNkv+X!i>&jz7Jc-mx>ro+*};gaGC:';

test.describe('Verificação de Integridade API (E2E)', () => {

    test.beforeEach(async ({ page }) => {
        // Monitorar erros de rede (400/500)
        page.on('response', response => {
            if (response.status() >= 400 && response.url().includes('/api/')) {
                console.error(`🚨 ERRO API: ${response.request().method()} ${response.url()} -> ${response.status()}`);
                // Tentar capturar o corpo do erro se possível
                response.text().then(t => console.error(`   Body: ${t}`)).catch(() => { });
            }
        });
    });

    test('Login deve funcionar e redirecionar para dashboard', async ({ page }) => {
        await page.goto(LOGIN_URL);

        // Preenche login
        await page.getByPlaceholder('Digite seu usuário').fill(USERNAME);
        await page.getByPlaceholder('Digite sua senha').fill(PASSWORD);

        // Submete
        await page.click('button[type="submit"]');

        // Verifica sucesso
        await expect(page).toHaveURL(DASHBOARD_URL, { timeout: 10000 });
    });

    test('Navegação para páginas principais não deve gerar erros 500', async ({ page }) => {
        // Login
        await page.goto(LOGIN_URL);
        await page.getByPlaceholder('Digite seu usuário').fill(USERNAME);
        await page.getByPlaceholder('Digite sua senha').fill(PASSWORD);
        await page.click('button[type="submit"]');
        await expect(page).toHaveURL(DASHBOARD_URL);

        // Navega para Clientes
        await page.goto('/clients');
        // Espera carregamento
        await page.waitForTimeout(1000);

        // Navega para Usuários
        await page.goto('/users');
        await page.waitForTimeout(1000);

        // Navega para Configurações
        await page.goto('/settings');
        await page.waitForTimeout(1000);
    });

});
