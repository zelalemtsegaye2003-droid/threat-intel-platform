#!/usr/bin/env python3
"""
Test script to verify all services are running correctly.
Run: python scripts/test_services.py
"""

import time
import sys

def test_service(name, host, port, timeout=5):
    """Test if a service is accessible."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"✓ {name} is running on port {port}")
            return True
        else:
            print(f"✗ {name} is NOT running on port {port}")
            return False
    except Exception as e:
        print(f"✗ {name} check failed: {e}")
        return False

def test_http(url, name, timeout=5):
    """Test HTTP endpoint."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=timeout)
        print(f"✓ {name} HTTP endpoint is accessible ({response.status})")
        return True
    except Exception as e:
        print(f"✗ {name} HTTP endpoint failed: {e}")
        return False

def main():
    print("=" * 60)
    print("ThreatIntel Platform - Service Test")
    print("=" * 60)
    print()
    
    results = []
    
    # Test Docker services
    services = [
        ("PostgreSQL", "localhost", 5432),
        ("Neo4j Bolt", "localhost", 7687),
        ("Neo4j HTTP", "localhost", 7474),
        ("Qdrant HTTP", "localhost", 6333),
        ("Qdrant gRPC", "localhost", 6334),
        ("Redis", "localhost", 6379),
        ("RabbitMQ", "localhost", 5672),
        ("RabbitMQ Management", "localhost", 15672),
    ]
    
    print("Testing Docker services...")
    for name, host, port in services:
        results.append(test_service(name, host, port))
    
    print()
    
    # Test HTTP APIs
    http_services = [
        ("Backend API", "http://localhost:8000/health"),
        ("Frontend", "http://localhost:3000"),
    ]
    
    print("Testing HTTP endpoints...")
    for name, url in http_services:
        results.append(test_http(url, name))
    
    print()
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} services are running")
    
    if passed < total:
        print("\nSome services are not running. Try:")
        print("  docker-compose up -d")
        print("  cd frontend && npm run dev")
        sys.exit(1)
    else:
        print("\nAll services are running! 🎉")
        sys.exit(0)

if __name__ == "__main__":
    main()
