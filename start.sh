#!/bin/bash
# Start ThreatIntel Platform

set -e

echo "🛡️  Starting ThreatIntel Platform..."
echo

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start Docker services
echo "📦 Starting Docker services..."
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 10

# Install frontend dependencies if needed
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend && npm install && cd ..
fi

# Initialize Qdrant collections
echo "🔧 Initializing Qdrant collections..."
python backend/scripts/init_qdrant.py || echo "⚠️  Qdrant init failed - will retry when API starts"

echo
echo "✅ Services started! Access the platform at:"
echo "   Frontend: http://localhost:3000"
echo "   API Docs: http://localhost:8000/docs"
echo "   RabbitMQ: http://localhost:15672 (guest/guest)"
echo
echo "To view logs: docker-compose logs -f [service_name]"
echo "To stop:     docker-compose down"
