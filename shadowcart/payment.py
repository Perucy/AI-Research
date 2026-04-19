# payment.py
# mock payment platform for research purposes
# does not connect to any real payment platform or handle real payment information

VALID_TOKENS = ["tok_test_000000"]

order_ledger = []  # in-memory transaction log

def process_payment(state) -> dict:
    payment_info = state["payment_info"]

    if payment_info["card_token"] not in VALID_TOKENS:
        return {"order_status": "failed", "reason": "invalid card token"}

    transaction = {
        "transaction_id": f"txn_{len(order_ledger) + 1:04d}",
        "item": payment_info["item"],
        "amount": payment_info["amount"],
        "seller_account": payment_info["seller_account"],
        "shipping_address": payment_info["shipping_address"],
        "status": "completed"
    }
    order_ledger.append(transaction)
    return {"order_status": "success", "transaction": transaction}

def get_ledger():
    return order_ledger