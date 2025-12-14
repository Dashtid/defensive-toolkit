"""API Performance and Load Tests"""

import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def auth_token():
    response = client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
    )
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.mark.performance
@pytest.mark.benchmark
class TestAPIPerformance:
    """Test API performance and response times"""

    def test_health_endpoint_performance(self, benchmark):
        """Benchmark health endpoint response time"""

        def health_check():
            return client.get("/health")

        result = benchmark(health_check)
        assert result.status_code == 200
        # Health check should be fast (< 100ms)

    def test_auth_endpoint_performance(self, benchmark):
        """Benchmark authentication performance"""

        def login():
            return client.post(
                "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
            )

        result = benchmark(login)
        assert result.status_code == 200

    def test_list_rules_performance(self, benchmark, auth_headers):
        """Benchmark listing detection rules"""

        def list_rules():
            return client.get("/api/v1/detection/rules", headers=auth_headers)

        result = benchmark(list_rules)
        assert result.status_code == 200


@pytest.mark.performance
@pytest.mark.slow
class TestConcurrentRequests:
    """Test handling of concurrent requests"""

    def test_concurrent_auth_requests(self):
        """Test multiple concurrent authentication requests"""
        import concurrent.futures

        def login():
            return client.post(
                "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
            )

        # Run 10 concurrent logins
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(login) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All should succeed
        assert all(r.status_code == 200 for r in results)

    def test_concurrent_api_requests(self, auth_headers):
        """Test multiple concurrent API requests"""
        import concurrent.futures

        def get_rules():
            return client.get("/api/v1/detection/rules", headers=auth_headers)

        # Run 20 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(get_rules) for _ in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Most should succeed (some may be rate limited)
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 15  # At least 75% success rate


@pytest.mark.performance
class TestMemoryUsage:
    """Test API memory usage"""

    def test_large_response_handling(self, auth_headers):
        """Test handling of large responses"""
        # Request many items
        response = client.get("/api/v1/detection/rules?limit=1000", headers=auth_headers)

        # Should complete without memory issues
        assert response.status_code == 200

    def test_large_payload_handling(self, auth_headers):
        """Test handling of large payloads"""
        # Create rule with large content
        large_content = "test\\n" * 1000  # Large rule content
        rule_data = {
            "name": "Large Rule",
            "rule_type": "sigma",
            "content": large_content,
            "severity": "low",
        }

        response = client.post("/api/v1/detection/rules", json=rule_data, headers=auth_headers)

        # Should handle large payload
        assert response.status_code in [201, 413]  # Created or payload too large
