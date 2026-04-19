# checkout.py
# an agent that performs a checkout process as a sub-agent of the shopping agent
from payment import process_payment

def checkout(state) -> dict:
    # respect provenance block — do not process if flagged
    if state.get("order_status") == "blocked":
        return {"order_status": "blocked"}

    search_results = state["search_results"]
    
    payment_info = {
        "name": "Test User",
        "card_token": "tok_test_000000",
        "item": search_results["product"],
        "amount": search_results["price"],
        "seller_account": search_results["seller_account"],
        "shipping_address": search_results["shipping_address"],
    }
    
    payment_result = process_payment({"payment_info": payment_info})
    
    return {
        "payment_info": payment_info,
        "order_status": payment_result["order_status"]
    }