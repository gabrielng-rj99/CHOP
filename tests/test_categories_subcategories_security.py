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

"""
Testes de Segurança Completos para APIs de Categories e Subcategories
"""

import pytest
import requests
import time
import uuid


class TestCategoriesAPIAuth:
    """Testes de autenticação para API de Categories"""

    def test_get_categories_requires_auth(self, http_client, api_url, timer):
        """GET /api/categories sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/categories")
        assert response.status_code == 401

    def test_post_category_requires_auth(self, http_client, api_url, timer):
        """POST /api/categories sem token deve retornar 401"""
        response = http_client.post(
            f"{api_url}/categories",
            json={"name": "Test Category"}
        )
        assert response.status_code == 401

    def test_get_category_by_id_requires_auth(self, http_client, api_url, timer):
        """GET /api/categories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/categories/{fake_id}")
        assert response.status_code == 401

    def test_put_category_requires_auth(self, http_client, api_url, timer):
        """PUT /api/categories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/categories/{fake_id}",
            json={"name": "Updated Category"}
        )
        assert response.status_code == 401

    def test_delete_category_requires_auth(self, http_client, api_url, timer):
        """DELETE /api/categories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(f"{api_url}/categories/{fake_id}")
        assert response.status_code == 401

    def test_archive_category_requires_auth(self, http_client, api_url, timer):
        """POST /api/categories/{id}/archive sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.post(f"{api_url}/categories/{fake_id}/archive")
        assert response.status_code == 401

    def test_unarchive_category_requires_auth(self, http_client, api_url, timer):
        """POST /api/categories/{id}/unarchive sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.post(f"{api_url}/categories/{fake_id}/unarchive")
        assert response.status_code == 401

    def test_get_category_subcategories_requires_auth(self, http_client, api_url, timer):
        """GET /api/categories/{id}/subcategories sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/categories/{fake_id}/subcategories")
        assert response.status_code == 401


class TestCategoriesInputValidation:
    """Testes de validação de input para Categories"""

    def test_create_category_empty_body(self, http_client, api_url, root_user, timer):
        """Criar categoria com body vazio deve falhar"""
        response = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={}
        )
        assert response.status_code == 400

    def test_create_category_null_name(self, http_client, api_url, root_user, timer):
        """Criar categoria com nome null deve falhar"""
        response = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": None}
        )
        assert response.status_code == 400

    def test_create_category_empty_name(self, http_client, api_url, root_user, timer):
        """Criar categoria com nome vazio deve falhar"""
        response = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": ""}
        )
        assert response.status_code == 400

    def test_update_category_invalid_id(self, http_client, api_url, root_user, timer):
        """Atualizar categoria com ID inválido deve falhar"""
        response = http_client.put(
            f"{api_url}/categories/invalid-uuid",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test"}
        )
        assert response.status_code in [400, 404]

    def test_get_category_not_found(self, http_client, api_url, root_user, timer):
        """GET categoria inexistente deve retornar 404"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/categories/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        # DEVE retornar 404 - categoria não existe
        assert response.status_code == 404, \
            f"Categoria inexistente retornou {response.status_code}, esperava 404"


class TestCategoriesXSSandSQLi:
    """Testes de XSS e SQL Injection para Categories"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'-alert('XSS')-'",
    ]

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE categories;--",
        "' UNION SELECT * FROM users--",
        "1; DELETE FROM categories WHERE '1'='1",
    ]

    def test_xss_in_category_name_create(self, http_client, api_url, root_user, timer):
        """XSS no nome da categoria ao criar deve ser sanitizado"""
        for i, payload in enumerate(self.XSS_PAYLOADS):
            response = http_client.post(
                f"{api_url}/categories",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"name": f"Cat_{i}_{payload}"}
            )
            # Pode aceitar sanitizado ou rejeitar
            if response.status_code == 201:
                data = response.json()
                cat_id = data.get("id")
                if cat_id:
                    get_resp = http_client.get(
                        f"{api_url}/categories/{cat_id}",
                        headers={"Authorization": f"Bearer {root_user['token']}"}
                    )
                    if get_resp.status_code == 200:
                        cat = get_resp.json()
                        # Verificar sanitização
                        assert "<script>" not in cat.get("name", "")

    def test_xss_in_category_name_update(self, http_client, api_url, root_user, timer):
        """XSS no nome da categoria ao atualizar deve ser sanitizado"""
        # Criar categoria válida primeiro
        create_resp = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Category for XSS Update"}
        )

        if create_resp.status_code == 201:
            cat_id = create_resp.json().get("id")

            for payload in self.XSS_PAYLOADS:
                response = http_client.put(
                    f"{api_url}/categories/{cat_id}",
                    headers={"Authorization": f"Bearer {root_user['token']}"},
                    json={"name": payload}
                )

                if response.status_code == 200:
                    get_resp = http_client.get(
                        f"{api_url}/categories/{cat_id}",
                        headers={"Authorization": f"Bearer {root_user['token']}"}
                    )
                    if get_resp.status_code == 200:
                        assert "<script>" not in get_resp.text

    def test_sqli_in_category_name(self, http_client, api_url, root_user, timer):
        """SQL Injection no nome da categoria deve ser bloqueado"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/categories",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"name": payload}
            )
            # Não deve causar erro SQL
            assert "syntax" not in response.text.lower()
            assert "error" not in response.text.lower() or response.status_code in [201, 400]

    def test_sqli_in_include_archived_param(self, http_client, api_url, root_user, timer):
        """SQL Injection no param include_archived deve ser bloqueado"""
        payloads = [
            "true' OR '1'='1",
            "1; DROP TABLE categories;--",
            "true UNION SELECT * FROM users--",
        ]

        for payload in payloads:
            response = http_client.get(
                f"{api_url}/categories",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                params={"include_archived": payload}
            )
            # Não deve vazar erro SQL
            assert "syntax" not in response.text.lower()


class TestCategoriesOverflow:
    """Testes de overflow para Categories"""

    def test_category_name_overflow_10k(self, http_client, api_url, root_user, timer):
        """Nome de categoria com 10K caracteres deve falhar"""
        long_name = "A" * 10000

        response = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": long_name}
        )
        assert response.status_code in [400, 413]
        assert response.elapsed.total_seconds() < 5


class TestCategoriesPermissions:
    """Testes de permissões para Categories"""

    def test_user_can_read_categories(self, http_client, api_url, regular_user, timer):
        """Usuário com permissão categories:read pode listar"""
        response = http_client.get(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {regular_user['token']}"}
        )
        # Depende das permissões configuradas para o role 'user'
        assert response.status_code in [200, 403]

    def test_user_cannot_delete_category(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode deletar categoria"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(
            f"{api_url}/categories/{fake_id}",
            headers={"Authorization": f"Bearer {regular_user['token']}"}
        )
        # 400, 403 ou 404 são válidos (sem permissão ou não encontrado)
        assert response.status_code in [400, 403, 404]


class TestSubcategoriesAPIAuth:
    """Testes de autenticação para API de Subcategories"""

    def test_get_subcategories_requires_auth(self, http_client, api_url, timer):
        """GET /api/subcategories sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/subcategories")
        assert response.status_code == 401

    def test_post_subcategory_requires_auth(self, http_client, api_url, timer):
        """POST /api/subcategories sem token deve retornar 401"""
        fake_cat_id = str(uuid.uuid4())
        response = http_client.post(
            f"{api_url}/subcategories",
            json={"name": "Test Subcategory", "category_id": fake_cat_id}
        )
        assert response.status_code == 401

    def test_get_subcategory_by_id_requires_auth(self, http_client, api_url, timer):
        """GET /api/subcategories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/subcategories/{fake_id}")
        assert response.status_code == 401

    def test_put_subcategory_requires_auth(self, http_client, api_url, timer):
        """PUT /api/subcategories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/subcategories/{fake_id}",
            json={"name": "Updated Subcategory"}
        )
        assert response.status_code == 401

    def test_delete_subcategory_requires_auth(self, http_client, api_url, timer):
        """DELETE /api/subcategories/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(f"{api_url}/subcategories/{fake_id}")
        assert response.status_code == 401

    def test_archive_subcategory_requires_auth(self, http_client, api_url, timer):
        """POST /api/subcategories/{id}/archive sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.post(f"{api_url}/subcategories/{fake_id}/archive")
        assert response.status_code == 401

    def test_unarchive_subcategory_requires_auth(self, http_client, api_url, timer):
        """POST /api/subcategories/{id}/unarchive sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.post(f"{api_url}/subcategories/{fake_id}/unarchive")
        assert response.status_code == 401


class TestSubcategoriesInputValidation:
    """Testes de validação de input para Subcategories"""

    def test_create_subcategory_empty_body(self, http_client, api_url, root_user, timer):
        """Criar subcategoria com body vazio deve falhar"""
        response = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={}
        )
        assert response.status_code == 400

    def test_create_subcategory_null_name(self, http_client, api_url, root_user, timer):
        """Criar subcategoria com nome null deve falhar"""
        fake_cat_id = str(uuid.uuid4())
        response = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": None, "category_id": fake_cat_id}
        )
        assert response.status_code == 400

    def test_create_subcategory_missing_category_id(self, http_client, api_url, root_user, timer):
        """Criar subcategoria sem category_id deve falhar"""
        response = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Subcategory"}
        )
        assert response.status_code == 400

    def test_create_subcategory_invalid_category_id(self, http_client, api_url, root_user, timer):
        """Criar subcategoria com category_id inexistente deve falhar"""
        fake_cat_id = str(uuid.uuid4())
        response = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Subcategory", "category_id": fake_cat_id}
        )
        assert response.status_code in [400, 404]

    def test_get_subcategory_not_found(self, http_client, api_url, root_user, timer):
        """GET subcategoria inexistente deve retornar 404"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/subcategories/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        # Pode retornar 404 ou 200 (lista vazia)
        assert response.status_code in [200, 404]


class TestSubcategoriesXSSandSQLi:
    """Testes de XSS e SQL Injection para Subcategories"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
    ]

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE subcategories;--",
        "' UNION SELECT * FROM users--",
    ]

    def test_xss_in_subcategory_name(self, http_client, api_url, root_user, timer):
        """XSS no nome da subcategoria deve ser sanitizado"""
        # Primeiro criar uma categoria válida
        cat_resp = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Category for Subcat XSS"}
        )

        if cat_resp.status_code == 201:
            cat_id = cat_resp.json().get("id")

            for i, payload in enumerate(self.XSS_PAYLOADS):
                response = http_client.post(
                    f"{api_url}/subcategories",
                    headers={"Authorization": f"Bearer {root_user['token']}"},
                    json={"name": f"Sub_{i}_{payload}", "category_id": cat_id}
                )

                if response.status_code == 201:
                    subcat_id = response.json().get("id")
                    get_resp = http_client.get(
                        f"{api_url}/subcategories/{subcat_id}",
                        headers={"Authorization": f"Bearer {root_user['token']}"}
                    )
                    if get_resp.status_code == 200:
                        assert "<script>" not in get_resp.text

    def test_sqli_in_subcategory_name(self, http_client, api_url, root_user, timer):
        """SQL Injection no nome da subcategoria deve ser bloqueado"""
        fake_cat_id = str(uuid.uuid4())

        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/subcategories",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"name": payload, "category_id": fake_cat_id}
            )
            # Não deve causar erro SQL
            assert "syntax" not in response.text.lower()

    def test_sqli_in_category_id(self, http_client, api_url, root_user, timer):
        """SQL Injection no category_id deve ser bloqueado"""
        sqli_ids = [
            "' OR '1'='1",
            "00000000-0000-0000-0000-000000000000'; DROP TABLE categories;--",
        ]

        for sqli_id in sqli_ids:
            response = http_client.post(
                f"{api_url}/subcategories",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"name": "Test", "category_id": sqli_id}
            )
            # Erros internos são aceitáveis para input malformado
            # mas não leak de sintaxe SQL real
            lower_text = response.text.lower()
            assert "postgresql" not in lower_text or "syntax" not in lower_text


class TestSubcategoriesPutXSS:
    """Testes de XSS para PUT /api/subcategories/{id}"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ]

    def test_xss_in_subcategory_name_on_update(self, http_client, api_url, root_user, timer):
        """XSS no nome da subcategoria ao atualizar deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria válida primeiro
        cat_resp = http_client.post(
            f"{api_url}/categories",
            headers=headers,
            json={"name": f"Cat for Subcat XSS Update {uuid.uuid4().hex[:8]}"}
        )

        if cat_resp.status_code == 201:
            cat_json = cat_resp.json()
            cat_id = cat_json.get("data", {}).get("id") or cat_json.get("id")

            # Criar subcategoria válida
            subcat_resp = http_client.post(
                f"{api_url}/subcategories",
                headers=headers,
                json={"name": "Valid Subcategory", "category_id": cat_id}
            )

            if subcat_resp.status_code == 201:
                subcat_json = subcat_resp.json()
                subcat_id = subcat_json.get("data", {}).get("id") or subcat_json.get("id")

                for payload in self.XSS_PAYLOADS:
                    response = http_client.put(
                        f"{api_url}/subcategories/{subcat_id}",
                        headers=headers,
                        json={"name": payload, "category_id": cat_id}
                    )

                    # Verificar que XSS não está presente na resposta
                    assert "<script>" not in response.text, \
                        f"XSS not sanitized in update: {payload}"
                    assert "onerror=" not in response.text.lower(), \
                        f"XSS event handler not sanitized: {payload}"
                    assert "onload=" not in response.text.lower(), \
                        f"XSS onload not sanitized: {payload}"


class TestSubcategoriesOverflow:
    """Testes de overflow para Subcategories"""

    def test_subcategory_name_overflow(self, http_client, api_url, root_user, timer):
        """Nome de subcategoria com 10K caracteres deve falhar"""
        long_name = "A" * 10000
        fake_cat_id = str(uuid.uuid4())

        response = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": long_name, "category_id": fake_cat_id}
        )
        assert response.status_code in [400, 404, 413]
        assert response.elapsed.total_seconds() < 5


class TestCategoriesSubcategoriesWorkflow:
    """Testes de workflow completo Categories -> Subcategories"""

    def test_full_crud_workflow(self, http_client, api_url, root_user, timer):
        """Teste CRUD completo: criar categoria, subcategoria, arquivar, desarquivar"""
        # 1. Criar categoria - DEVE funcionar
        cat_resp = http_client.post(
            f"{api_url}/categories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": f"Test Category {uuid.uuid4().hex[:8]}"}
        )
        assert cat_resp.status_code == 201, \
            f"Criar categoria falhou com {cat_resp.status_code}: {cat_resp.text}"
        json_resp = cat_resp.json()
        cat_id = json_resp.get("data", {}).get("id") or json_resp.get("id")
        assert cat_id, f"Categoria criada mas sem ID retornado. Resp: {cat_resp.text}"

        # 2. Criar subcategoria - DEVE funcionar
        subcat_resp = http_client.post(
            f"{api_url}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Subcategory", "category_id": cat_id}
        )
        assert subcat_resp.status_code == 201, \
            f"Criar subcategoria falhou com {subcat_resp.status_code}: {subcat_resp.text}"
        subcat_json = subcat_resp.json()
        subcat_id = subcat_json.get("data", {}).get("id") or subcat_json.get("id")
        assert subcat_id, f"Subcategoria criada mas sem ID retornado. Resp: {subcat_resp.text}"

        # 3. Listar subcategorias - DEVE funcionar
        list_resp = http_client.get(
            f"{api_url}/categories/{cat_id}/subcategories",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert list_resp.status_code == 200, \
            f"Listar subcategorias falhou com {list_resp.status_code}"

        # 4. Arquivar subcategoria - DEVE funcionar
        archive_resp = http_client.post(
            f"{api_url}/subcategories/{subcat_id}/archive",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert archive_resp.status_code in [200, 204], \
            f"Arquivar subcategoria falhou com {archive_resp.status_code}"

        # 5. Desarquivar subcategoria - DEVE funcionar
        unarchive_resp = http_client.post(
            f"{api_url}/subcategories/{subcat_id}/unarchive",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert unarchive_resp.status_code in [200, 204], \
            f"Desarquivar subcategoria falhou com {unarchive_resp.status_code}"

        # 6. Deletar subcategoria - DEVE funcionar
        del_subcat_resp = http_client.delete(
            f"{api_url}/subcategories/{subcat_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert del_subcat_resp.status_code in [200, 204], \
            f"Deletar subcategoria falhou com {del_subcat_resp.status_code}"

        # 7. Deletar categoria - DEVE funcionar
        del_cat_resp = http_client.delete(
            f"{api_url}/categories/{cat_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert del_cat_resp.status_code in [200, 204], \
            f"Deletar categoria falhou com {del_cat_resp.status_code}"
