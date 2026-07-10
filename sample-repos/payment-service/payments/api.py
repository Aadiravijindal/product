"""HTTP surface for the payments service (internal — behind the gateway)."""

import json
import time

from flask import Flask, request, jsonify

from payments.signer import generate_keys, sign_transaction

app = Flask(__name__)

_PRIVATE_KEY = generate_keys()


@app.post("/v1/settlements")
def create_settlement():
    payload = request.get_json(force=True)
    tx = {
        "merchant_id": payload["merchant_id"],
        "amount_cents": int(payload["amount_cents"]),
        "currency": payload.get("currency", "USD"),
        "ts": int(time.time()),
    }
    tx_bytes = json.dumps(tx, sort_keys=True).encode()
    signature = sign_transaction(_PRIVATE_KEY, tx_bytes)
    return jsonify(
        {
            "transaction": tx,
            "signature": signature.hex(),
        }
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
