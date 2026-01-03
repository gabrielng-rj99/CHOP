# =============================================================================
# Client Hub Open Project
# Copyright (C) 2025 Client Hub Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

import pytest
import requests
import time

@pytest.mark.sql_injection
@pytest.mark.security
class TestSQLInjection:
    """Testes de SQL Injection com payloads reais"""

    # Payloads de SQL injection comuns
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "' OR 'x'='x",
        "1' OR '1' = '1",
        "' OR 1=1 LIMIT 1 --",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT * FROM users--",
        "'; DROP TABLE users; --",
        "'; DELETE FROM users WHERE 1=1; --",
        "'; EXEC sp_MSForEachTable 'DROP TABLE ?'; --",
        "1; DELETE FROM users WHERE 1=1 --",
        "1' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "admin' AND 1=0 UNION ALL SELECT 'admin', 'password'",
        "' UNION SELECT username, password FROM users--",
        "' AND (SELECT COUNT(*) FROM users) > 0 --",
        "' AND 1=(SELECT COUNT(*) FROM users) --",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 100--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--",
        "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)--",
        "'; DECLARE @q VARCHAR(8000) SELECT @q = 0x73656c656374202740407665727369 EXEC(@q)--",
        "1'; SELECT pg_sleep(5); --",
        "1' AND (SELECT 1 FROM pg_sleep(5))--",
        "' OR 1=1; SELECT * FROM users WHERE 'a'='a",
        "' UNION SELECT NULL, username, password FROM users--",
        "1' AND 'x'='x",
        "1' AND 'x'='y",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "admin' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>0--",
        "' OR 1=1 INTO OUTFILE '/tmp/test.txt'--",
        "' UNION SELECT load_file('/etc/passwd')--",
    ]

    def test_sql_injection_in_login_username(self, http_client, api_url, timer):
        """Testar SQL injection no campo username do login"""
        injection_blocked = True

        for payload in self.SQL_PAYLOADS[:10]:  # Primeiros 10 payloads
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test123"
            })

            # Se retornou 200 com token, VULNERÁVEL
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "access_token" in data or "token" in data:
                        injection_blocked = False
                        pytest.fail(f"VULNERÁVEL: SQL injection funcionou com payload: {payload}")
                except:
                    pass

        assert injection_blocked, "Sistema deveria bloquear SQL injection no login"

    def test_sql_injection_in_login_password(self, http_client, api_url, timer):
        """Testar SQL injection no campo password do login"""
        injection_blocked = True

        for payload in self.SQL_PAYLOADS[:10]:
            response = http_client.post(f"{api_url}/login", json={
                "username": "admin",
                "password": payload
            })

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "access_token" in data or "token" in data:
                        injection_blocked = False
                        pytest.fail(f"VULNERÁVEL: SQL injection em password: {payload}")
                except:
                    pass

        assert injection_blocked, "Sistema deveria bloquear SQL injection em password"

    def test_sql_injection_in_search_params(self, http_client, api_url, root_user, timer):
        """Testar SQL injection em parâmetros de busca"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:15]:
            response = http_client.get(
                f"{api_url}/users",
                params={"search": payload},
                headers=headers
            )

            # Não deve retornar 500 (erro de SQL)
            # Não deve vazar informações do banco
            assert response.status_code != 500, f"Erro 500 pode indicar SQL injection: {payload}"

            if response.status_code == 200:
                data = response.json()
                # Não deve retornar dados suspeitos
                if isinstance(data, list) and len(data) > 1000:
                    pytest.fail(f"Possível SQL injection: retornou dados demais com: {payload}")

    def test_sql_injection_in_client_creation(self, http_client, api_url, root_user, timer):
        """Testar SQL injection ao criar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        dangerous_payloads = [
            "'; DROP TABLE clients; --",
            "'; DELETE FROM clients WHERE 1=1; --",
            "' UNION SELECT * FROM users--",
        ]

        for payload in dangerous_payloads:
            response = http_client.post(f"{api_url}/clients", json={
                "name": payload,
                "email": "test@test.com"
            }, headers=headers)

            # Deve rejeitar ou sanitizar
            assert response.status_code in [200, 201, 400], "Não deve causar erro de SQL"

            # Verificar que tabela não foi dropada tentando buscar clientes
            check_response = http_client.get(f"{api_url}/clients", headers=headers)
            assert check_response.status_code == 200, "Tabela de clientes não deve ser afetada"

    def test_sql_injection_in_user_creation(self, http_client, api_url, root_user, timer):
        """Testar SQL injection ao criar usuário"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:5]:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"test_{int(time.time())}",
                "display_name": payload,
                "password": "Test123!@#",
                "role": "user"
            }, headers=headers)

            # Não deve causar erro SQL
            assert response.status_code in [200, 201, 400], "Não deve causar erro SQL"

    def test_sql_injection_in_category_name(self, http_client, api_url, root_user, timer):
        """Testar SQL injection em nome de categoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:5]:
            response = http_client.post(f"{api_url}/categories", json={
                "name": payload
            }, headers=headers)

            assert response.status_code in [200, 201, 400], "Não deve causar erro SQL"

    def test_sql_injection_in_contract_search(self, http_client, api_url, root_user, timer):
        """Testar SQL injection em busca de contratos"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:10]:
            response = http_client.get(
                f"{api_url}/contracts",
                params={"item_key": payload},
                headers=headers
            )

            assert response.status_code in [200, 404], "Não deve causar erro SQL"

    def test_union_based_sql_injection(self, http_client, api_url, timer):
        """Testar UNION-based SQL injection no login"""
        union_payloads = [
            "admin' UNION SELECT 'admin', 'password', 'root'--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT username, password, role FROM users--",
        ]

        for payload in union_payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "anything"
            })

            if response.status_code == 200:
                data = response.json()
                if "access_token" in data:
                    pytest.fail(f"VULNERÁVEL a UNION injection: {payload}")

    def test_time_based_blind_sql_injection(self, http_client, api_url, timer):
        """Testar time-based blind SQL injection"""
        time_payloads = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ]

        for payload in time_payloads:
            start = time.time()
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            }, timeout=10)
            duration = time.time() - start

            # Se demorou muito (>4s), pode ser vulnerável
            if duration > 4:
                pytest.fail(f"Possível time-based SQL injection: {payload} (durou {duration}s)")

    def test_boolean_based_blind_sql_injection(self, http_client, api_url, timer):
        """Testar boolean-based blind SQL injection"""
        # Payload TRUE vs FALSE devem ter respostas diferentes
        true_payload = "admin' AND '1'='1"
        false_payload = "admin' AND '1'='2"

        response_true = http_client.post(f"{api_url}/login", json={
            "username": true_payload,
            "password": "test"
        })

        response_false = http_client.post(f"{api_url}/login", json={
            "username": false_payload,
            "password": "test"
        })

        # Se as respostas forem diferentes, pode indicar vulnerabilidade
        # Mas ambas devem ser 401 (não autenticado)
        assert response_true.status_code == 401, "TRUE condition deve retornar 401"
        assert response_false.status_code == 401, "FALSE condition deve retornar 401"

    def test_stacked_queries_sql_injection(self, http_client, api_url, timer):
        """Testar stacked queries (múltiplos comandos)"""
        stacked_payloads = [
            "admin'; DELETE FROM audit_logs WHERE 1=1; --",
            "test'; UPDATE users SET role='root' WHERE username='test'; --",
            "'; CREATE TABLE hacked (id INT); --",
        ]

        for payload in stacked_payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            })

            # Não deve executar múltiplos comandos
            assert response.status_code in [401, 400], "Stacked queries devem ser bloqueadas"

    def test_sql_injection_with_encoded_payloads(self, http_client, api_url, timer):
        """Testar SQL injection com payloads encoded"""
        import urllib.parse

        encoded_payloads = [
            urllib.parse.quote("' OR '1'='1"),
            urllib.parse.quote("admin'--"),
            urllib.parse.quote("'; DROP TABLE users; --"),
        ]

        for payload in encoded_payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            })

            if response.status_code == 200:
                pytest.fail(f"Vulnerável a SQL injection com payload encoded: {payload}")

    def test_sql_injection_in_order_by_clause(self, http_client, api_url, root_user, timer):
        """Testar SQL injection em ORDER BY"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        order_payloads = [
            "1--",
            "1 DESC--",
            "(SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)",
            "1 AND SLEEP(5)",
        ]

        for payload in order_payloads:
            response = http_client.get(
                f"{api_url}/users",
                params={"order": payload},
                headers=headers
            )

            assert response.status_code in [200, 400], "ORDER BY injection deve ser tratada"

    def test_sql_injection_with_comments(self, http_client, api_url, timer):
        """Testar SQL injection usando comentários SQL"""
        comment_payloads = [
            "admin'/*",
            "admin'#",
            "admin'-- ",
            "admin'/**/OR/**/1=1--",
            "admin'/*!50000OR*/1=1--",
        ]

        for payload in comment_payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            })

            if response.status_code == 200:
                pytest.fail(f"Vulnerável a SQL injection com comentários: {payload}")

    def test_no_sql_error_messages_leaked(self, http_client, api_url, timer):
        """Verificar que mensagens de erro SQL não vazam"""
        error_inducing_payloads = [
            "admin'",
            "admin''",
            "admin'\"",
            "admin';",
        ]

        # Keywords that indicate SQL error leakage (not generic error messages)
        sql_error_keywords = [
            "sql syntax",
            "syntax error",
            "postgresql",
            "postgres",
            "pg_catalog",
            "pg_class",
            "relation \"",
            "column \"",
            "query failed",
            "database error",
            "sql error",
            "pq:",  # PostgreSQL driver prefix
            "sqlstate",
            "unterminated",
            "unexpected token",
        ]

        for payload in error_inducing_payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            })

            response_text = response.text.lower()

            for keyword in sql_error_keywords:
                if keyword in response_text:
                    pytest.fail(f"Possível vazamento de erro SQL: '{keyword}' encontrado na resposta com payload: {payload}")
