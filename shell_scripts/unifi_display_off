#!/bin/bash

# CONFIGURATION
UNIFI_HOST="https://192.168.1.100"
USERNAME="yourusername"
PASSWORD="yourpassord"
# UPDATE DISPLAY ID
DISPLAY_ID="b98280c4-f7c7-3c58-aa43-adf1621049d1"

# TEMP FILES
COOKIE_JAR=$(mktemp)

# Function to decode JWT and extract CSRF token
extract_csrf_from_token() {
  local jwt_token="$1"
  local payload=$(echo "$jwt_token" | cut -d '.' -f2 | base64 -d 2>/dev/null)
  echo "$payload" | grep -o '"csrfToken":"[^"]*"' | cut -d':' -f2 | tr -d '"'
}

# LOGIN
echo "🔐 Logging in to UniFi Connect..."
LOGIN_RESPONSE=$(curl -sk \
  -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" \
  -X POST "$UNIFI_HOST/api/auth/login" \
  --data "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

if echo "$LOGIN_RESPONSE" | grep -q '"unique_id"'; then
  echo "✅ Login successful. Session cookie received."
else
  echo "❌ Login failed. Response:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

# EXTRACT TOKEN COOKIE
TOKEN_COOKIE=$(grep "TOKEN" "$COOKIE_JAR" | awk '{print $NF}')
if [ -z "$TOKEN_COOKIE" ]; then
  echo "❌ TOKEN cookie not found"
  exit 1
fi

# EXTRACT CSRF TOKEN FROM JWT
echo "🔑 Extracting CSRF token from JWT..."
CSRF_TOKEN=$(extract_csrf_from_token "$TOKEN_COOKIE")
if [ -z "$CSRF_TOKEN" ]; then
  echo "❌ Failed to extract CSRF token"
  exit 1
fi

echo "🔑 CSRF token: $CSRF_TOKEN"

# SEND PATCH REQUEST TO TURN OFF DISPLAY
echo "📡 Sending 'display_off' PATCH request..."

# UPDATE DISPLAY ID

PATCH_PAYLOAD="{\"id\":\"ea959362-c56f-4932-ab8b-0f512a93460c\",\"name\":\"display_off\",\"args\":{}}"

RESPONSE=$(curl -sk -X PATCH "$UNIFI_HOST/proxy/connect/api/v2/devices/$DISPLAY_ID/status" \
  -b "$COOKIE_JAR" \
  -H "Content-Type: application/json; charset=utf-8" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -H "Origin: $UNIFI_HOST" \
  --data "$PATCH_PAYLOAD")

echo "📨 Response:"
echo "$RESPONSE"

# CLEAN UP
rm -f "$COOKIE_JAR"
