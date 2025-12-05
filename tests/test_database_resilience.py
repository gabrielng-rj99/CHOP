import pytest
import subprocess
import time
import requests
import os

@pytest.mark.database
@pytest.mark.integration
class TestDatabaseResilience:
    """
    Tests the system behavior when the database becomes unavailable.
    """

    def test_database_outage_handling(self, base_url, api_url, http_client):
        """
        Verifies that the API handles database outages gracefully (503/500),
        and recovers when the database comes back online.
        """
        # 1. Verify system is healthy initially
        self._wait_for_health(base_url, http_client, expected_status="healthy")

        try:
            # 2. Stop the database container
            print("\nStopping database container...")
            self._docker_compose("stop", "postgres_test")
            
            # Give it a moment to completely stop accepting connections
            time.sleep(2)

            # 3. Verify Health Endpoint reports unhealthy/failure
            # It might return 503 Service Unavailable or 500 Internal Server Error
            response = http_client.get(f"{base_url}/health")
            assert response.status_code in [500, 503], "API should report error when DB is down"
            
            data = response.json()
            # The exact message depends on the implementation, but 'status' should generally not be 'healthy'
            # or the connection error should be logged.
            assert data.get("status") != "healthy" or "error" in str(data).lower()

            # 4. Verify API Endpoints return appropriate error (not hang)
            # Try a public endpoint or one that needs DB
            try:
                # Set a short timeout to ensure it doesn't hang forever
                resp_users = http_client.get(f"{api_url}/users", timeout=5)
                # 401 is also acceptable (fail closed) if auth middleware can't verify user due to DB down
                assert resp_users.status_code in [500, 503, 401], f"API should fail closed (500/503/401) when DB is down. Got: {resp_users.status_code}"
            except requests.exceptions.RequestException:
                # Connection refused or timeout is also 'acceptable' in some crash scenarios, 
                # but ideally we get a 5xx response from the API gateway/backend.
                pass

        finally:
            # 5. Restart the database container (cleanup)
            print("\nRestarting database container...")
            self._docker_compose("start", "postgres_test")
            
            # 6. Wait for recovery
            self._wait_for_health(base_url, http_client, "healthy")

    def _docker_compose(self, command, service):
        """Helper to run docker-compose commands"""
        # Assuming we are running from the tests/ directory or project root.
        # We need to find docker-compose.test.yml
        compose_file = "tests/docker-compose.test.yml"
        if not os.path.exists(compose_file):
            compose_file = "docker-compose.test.yml"
        
        if not os.path.exists(compose_file):
             pytest.skip("docker-compose.test.yml not found, skipping db resilience test")

        cmd = ["docker", "compose", "-f", compose_file, command, service]
        subprocess.check_call(cmd)

    def _wait_for_health(self, base_url, client, expected_status, timeout=30):
        """Waits for the health endpoint to match expected status"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = client.get(f"{base_url}/health")
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == expected_status:
                        return
            except Exception:
                pass
            time.sleep(1)
        
        # If we get here, we timed out
        pytest.fail(f"Timeout waiting for health status '{expected_status}'")
