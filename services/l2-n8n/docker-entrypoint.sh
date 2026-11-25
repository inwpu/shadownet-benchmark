#!/bin/bash









set -u

BASE_URL="http://127.0.0.1:5678"
EMAIL="admin@vulhub.org"
PASSWORD="N8n7Qa2Vx9Rm4Lk8Pz3Wt6Hy1"
COOKIES=/tmp/n8n-cookies.txt

login() {
  rm -f "$COOKIES"
  curl -s -X POST "$BASE_URL/rest/login" \
    -H "Content-Type: application/json" -c "$COOKIES" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    | grep -q '"id"'
}

wait_ready() {
  local i=0
  while [ $i -lt 90 ]; do
    curl -sf "$BASE_URL/rest/settings" | grep -q versionCli && return 0
    sleep 2
    i=$((i + 1))
  done
  return 1
}

start_n8n() {
  n8n start &
  N8N_PID=$!
  echo "[*] Waiting for n8n to start..."
  wait_ready || echo "[!] n8n did not report ready"
}

create_workflow() {
  local resp id
  resp=$(curl -s -X POST "$BASE_URL/rest/workflows" \
    -H "Content-Type: application/json" -b "$COOKIES" \
    -d '{
      "name": "Document Submission Portal",
      "nodes": [
        {"parameters": {"formTitle": "Document Submission",
          "formDescription": "Please fill out the form below and upload your document.",
          "responseMode": "responseNode",
          "formFields": {"values": [
            {"fieldLabel": "Full Name", "fieldType": "text",
             "requiredField": true, "placeholder": "John Doe"},
            {"fieldLabel": "Email", "fieldType": "email",
             "requiredField": true, "placeholder": "john@example.com"},
            {"fieldLabel": "document", "fieldType": "file",
             "requiredField": true,
             "acceptFileTypes": ".pdf,.doc,.docx,.txt,.png,.jpg",
             "multipleFiles": false}]}},
         "id": "d4a7c1e2-8f3b-4a5c-9d6e-7f8a0b1c2d3e",
         "name": "Form Trigger", "type": "n8n-nodes-base.formTrigger",
         "typeVersion": 2.2, "position": [260, 340],
         "webhookId": "vulnerable-form"},
        {"parameters": {"values": {"string": [
            {"name": "status", "value": "received"},
            {"name": "processedAt", "value": "={{ new Date().toISOString() }}"}]},
          "options": {}},
         "id": "b5e9f2a3-6c4d-4e7f-8a1b-9c0d2e3f4a5b",
         "name": "Log Submission", "type": "n8n-nodes-base.set",
         "typeVersion": 2, "position": [520, 340]},
        {"parameters": {"respondWith": "binary",
          "inputDataFieldName": "document"},
         "id": "c6f0a3b4-7d5e-4f8a-9b2c-0d1e3f4a5b6c",
         "name": "Return Document", "type": "n8n-nodes-base.respondToWebhook",
         "typeVersion": 1.1, "position": [780, 340]}],
      "connections": {
        "Form Trigger": {"main": [[{"node": "Log Submission",
                                    "type": "main", "index": 0}]]},
        "Log Submission": {"main": [[{"node": "Return Document",
                                      "type": "main", "index": 0}]]}},
      "active": false, "settings": {"executionOrder": "v1"}, "pinData": {}}')
  id=$(printf '%s' "$resp" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -n "$id" ]; then
    curl -s -X PATCH "$BASE_URL/rest/workflows/$id" \
      -H "Content-Type: application/json" -b "$COOKIES" \
      -d '{"active": true}' >/dev/null
    echo "[+] Workflow recreated: $id"
    return 0
  fi
  echo "[!] Workflow creation failed"
  return 1
}

ensure_workflow() {
  local listing
  listing=$(curl -s -b "$COOKIES" "$BASE_URL/rest/workflows")
  local id
  id=$(printf '%s' "$listing" | grep -o '"id":"[^"]*","name":"[^"]*"' \
       | grep -i 'document submission' | head -1 | cut -d'"' -f4)
  if [ -z "$id" ]; then
    id=$(printf '%s' "$listing" | grep -o '"id":"[^"]*"' | head -1 \
         | cut -d'"' -f4)
  fi
  if [ -z "$id" ]; then
    create_workflow
    return
  fi
  curl -s -X PATCH "$BASE_URL/rest/workflows/$id" \
    -H "Content-Type: application/json" -b "$COOKIES" \
    -d '{"active": true}' >/dev/null
}

start_n8n

if ! login; then
  echo "[!] owner login failed; resetting n8n user state"
  kill "$N8N_PID" 2>/dev/null
  wait "$N8N_PID" 2>/dev/null
  n8n user-management:reset >/dev/null 2>&1 || true
  start_n8n
  curl -s -X POST "$BASE_URL/rest/owner/setup" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"firstName\":\"Admin\",\"lastName\":\"Vulhub\",\"password\":\"$PASSWORD\"}" \
    >/dev/null 2>&1 || true
  login || echo "[!] owner setup failed"
fi

if login; then
  ensure_workflow
else
  echo "[!] running without an authenticated owner; workflow may be unavailable"
fi



(
  fails=0
  while sleep 60; do
    if login; then
      fails=0
      ensure_workflow
    else
      fails=$((fails + 1))
      if [ "$fails" -ge 2 ]; then
        echo "[!] owner login keeps failing; restarting container"
        kill "$N8N_PID" 2>/dev/null
        exit 0
      fi
    fi
  done
) &
RECONCILE_PID=$!

echo "[+] Lab ready! Form at: http://localhost:5678/form/vulnerable-form"
wait "$N8N_PID"
kill "$RECONCILE_PID" 2>/dev/null || true
