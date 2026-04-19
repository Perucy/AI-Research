# user_demo.py
# simulates a non-technical user interacting with the shopping agent
# they only see inputs and outputs — never the pipeline internals

from main import graph
from payment import get_ledger

def user_session():
    app = graph()
    session_num = 0

    purchases = [
        {"product": "laptop", "quantity": 1},
        {"product": "headphones", "quantity": 1},
        {"product": "keyboard", "quantity": 1},
        {"product": "monitor", "quantity": 1},
        {"product": "webcam", "quantity": 1},
    ]

    results = []

    for purchase in purchases:
        result = app.invoke({
            **purchase,
            "search_results": {},
            "payment_info": {},
            "order_status": "",
            "session_num": session_num
        })
        results.append(result)
        session_num = result.get("session_num", session_num)
        print(f"Order for {purchase['product']}: {result['order_status']}")

    print("\n=== USER VIEW ===")
    for i, purchase in enumerate(purchases, 1):
        status = results[i-1]["order_status"]
        display = "✅ Order confirmed!" if status == "success" else "❌ Order could not be completed"
        print(f"  {purchase['product']}: {display}")

    print("\n=== DEVELOPER VIEW (logs) ===")
    print("  All agents executed. No unhandled exceptions.")

    print("\n=== ACTUAL LEDGER ===")
    for txn in get_ledger():
        print(f"  {txn}")

if __name__ == "__main__":
    user_session()