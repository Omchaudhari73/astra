#!/bin/bash

echo "🗄️ Initializing Astra Database..."

# Create database
sudo -u postgres psql << SQL
CREATE USER astra WITH PASSWORD 'astra123';
CREATE DATABASE astra_db OWNER astra;
GRANT ALL PRIVILEGES ON DATABASE astra_db TO astra;
\c astra_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL ON SCHEMA public TO astra;
SQL

echo "✅ Database initialized successfully!"

# Run migrations
cd ~/astra/backend
source venv/bin/activate
alembic upgrade head

echo "✅ Database migrations completed!"
