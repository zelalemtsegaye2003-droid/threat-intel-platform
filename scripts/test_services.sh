#!/usr/bin/env bash
# test_services.sh — Test all platform services
# Usage: ./scripts/test_services.sh [--no-color]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

log_pass() {
    echo -e "${GREEN}  ✓ $1${NC} (${TOTAL}/${PASS})"
    ((PASS++))
}

log_fail() {
    echo -e "${RED}  ✗ $1${NC}"
    ((FAIL++))
}

log_test() {
    ((TOTAL++))
    echo -e "${YELLOW}Testing:${NC} $1..."
}

# --- Configuration ---
API_BASE="${THREAT_INTEL_API:-http://localhost:8000}"
FRONTEND="${THREAT_INTEL_FRONTEND:-http://localhost:3000}"
METRICS="${THREAT_INTEL_METRICS:-http://localhost:9090}"
GRAFANA="${THREAT_INTEL_GRAFANA:-http://localhost:3001}"
FLOWER="${THREAT_INTEL_FLOWER:-http://localhost:5555}"

# --- Test Functions ---

test_api_root() {
    log_test "API Root Endpoint"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/")
    [[ "$status" == "200" ]] && log_pass "API root returns 200" || log_fail "Expected 200, got $status"
}

test_api_health() {
    log_test "API Health Check"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/health")
    [[ "$status" == "200" ]] && log_pass "Health check returns 200" || log_fail "Expected 200, got $status"
}

test_api_deep_health() {
    log_test "Deep Health Check"
    local response
    response=$(curl -s "${API_BASE}/health/deep")
    echo "$response" | grep -q '"status"' && log_pass "Deep health returns status" || log_fail "Deep health missing status"
    echo "$response" | grep -q '"services"' && log_pass "Deep health returns services" || log_fail "Deep health missing services"
}

test_api_metrics() {
    log_test "Prometheus Metrics"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/metrics")
    [[ "$status" == "200" ]] && log_pass "Metrics endpoint returns 200" || log_fail "Expected 200, got $status"
    local content
    content=$(curl -s "${API_BASE}/metrics")
    echo "$content" | grep -q '# HELP' && log_pass "Metrics returns valid Prometheus data" || log_fail "Invalid metrics format"
}

test_api_iocs() {
    log_test "IOCs CRUD"
    local status
    # List
    status=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/iocs/")
    [[ "$status" == "200" ]] && log_pass "IOCs list returns 200" || log_fail "Expected 200, got $status"
    # Create
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API_BASE}/iocs/" \
        -H "Content-Type: application/json" \
        -d '{"type":"ipv4","value":"10.0.0.1","threat_level":"medium","source":"test"}')
    [[ "$status" == "200" ]] && log_pass "IOC create returns 200" || log_fail "Expected 200, got $status"
}

test_api_auth() {
    log_test "Auth Endpoints"
    local status
    # Login
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API_BASE}/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin123"}')
    [[ "$status" == "200" ]] && log_pass "Login endpoint returns 200" || log_fail "Expected 200, got $status"
    # Register
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API_BASE}/auth/register" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","email":"test@test.com","password":"testpass123"}')
    [[ "$status" == "200" || "$status" == "400" ]] && log_pass "Register endpoint responds" || log_fail "Expected 200/400, got $status"
}

test_api_pagination() {
    log_test "Pagination Support"
    local response
    response=$(curl -s "${API_BASE}/iocs/?page=1&page_size=1&active_only=false")
    echo "$response" | grep -q '"page"' && log_pass "Pagination metadata present" || log_fail "Missing pagination metadata"
    echo "$response" | grep -q '"total"' && log_pass "Total count present" || log_fail "Missing total count"
}

test_observability() {
    log_test "Observability Stack"
    # Prometheus
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${METRICS}/")
    [[ "$status" == "200" ]] && log_pass "Prometheus accessible" || log_fail "Prometheus not accessible at $METRICS"
    # Grafana
    status=$(curl -s -o /dev/null -w "%{http_code}" "${GRAFANA}/")
    [[ "$status" == "200" ]] && log_pass "Grafana accessible" || log_fail "Grafana not accessible at $GRAFANA"
    # Flower
    status=$(curl -s -o /dev/null -w "%{http_code}" "${FLOWER}/")
    [[ "$status" == "200" ]] && log_pass "Celery Flower accessible" || log_fail "Flower not accessible at $FLOWER"
}

test_frontend() {
    log_test "Frontend"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${FRONTEND}/")
    [[ "$status" == "200" ]] && log_pass "Frontend returns 200" || log_fail "Expected 200, got $status"
}

# --- Run Tests ---
echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║   Threat Intelligence Platform — Service Tests   ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Quick checks (no Docker required)
test_api_root
test_api_health
test_api_deep_health
test_api_metrics
test_api_auth
test_api_iocs
test_api_pagination

# Optional — observability stack
test_observability

# Optional — frontend
test_frontend

# --- Summary ---
echo ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results: ${GREEN}${PASS}/${TOTAL} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi