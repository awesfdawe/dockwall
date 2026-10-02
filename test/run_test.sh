set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${DIR}/.." && pwd)"

cleanup() {
    docker compose -f "${DIR}/docker-compose.test.yml" down -v --remove-orphans 2>/dev/null || true
    pkill -f "${ROOT_DIR}/bin/dockwall" 2>/dev/null || true
}
trap cleanup EXIT

cleanup

docker compose -f "${DIR}/docker-compose.test.yml" up -d

go build -trimpath -ldflags="-s -w" -o "${ROOT_DIR}/bin/dockwall" "${ROOT_DIR}/cmd/dockwall"
sudo "${ROOT_DIR}/bin/dockwall" -config "${DIR}/test_config.yaml" &
sleep 2

docker exec reverse-proxy nc -z -w 2 service-a 8080
docker exec reverse-proxy nc -z -w 2 service-b 8080

if docker exec service-a nc -z -w 2 service-b 8080 2>/dev/null; then
    echo "FAIL: service-a could reach service-b"
    exit 1
fi

if docker exec service-a nc -z -w 2 reverse-proxy 80 2>/dev/null; then
    echo "FAIL: service-a could reach reverse-proxy"
    exit 1
fi

docker exec client-a nc -z -w 2 xray-core 9090
docker exec client-b nc -z -w 2 xray-core 9090

if docker exec client-a nc -z -w 2 client-b 9090 2>/dev/null; then
    echo "FAIL: client-a could reach client-b"
    exit 1
fi

echo "ALL TESTS PASSED"
