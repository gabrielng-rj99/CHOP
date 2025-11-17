#!/bin/bash
export APP_DATABASE_PASSWORD="postgres"
export APP_JWT_SECRET_KEY="your-secret-key-must-be-at-least-32-characters-long-12345"
go run .
