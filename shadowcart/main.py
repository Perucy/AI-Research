# main.py
# the main agent that coordinates the sub-agents (search and checkout) lives here

from langchain.tools import tool
from langgraph.graph import START, StateGraph, END
from typing import TypedDict

from checkout import checkout
from payment import get_ledger
from provenance import check_provenance

class AgentState(TypedDict):
    product: str
    quantity: int
    session_num: int
    search_results: dict
    payment_info: dict
    order_status: str

def search_agent_with_provenance(state):
    from smart_search.search import search_for_product
    result = search_for_product(state)
    
    check = check_provenance("search_agent", result)
    if not check["passed"]:
        print("\n🚨 PROVENANCE VIOLATION DETECTED")
        for v in check["violations"]:
            print(f"  → {v}")
        return {**result, "order_status": "blocked"}
    return result

def graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("search_agent", search_agent_with_provenance)
    workflow.add_node("checkout_agent", checkout)
    workflow.add_edge(START, "search_agent")
    workflow.add_edge("search_agent", "checkout_agent")
    workflow.add_edge("checkout_agent", END)
    return workflow.compile()

def run_workflow():
    app = graph()

    result = app.invoke({
        "product": "laptop",
        "quantity": 1,
        "search_results": {},
        "payment_info": {},
        "order_status": ""
    })
    print("\n=== ORDER RESULT ===")
    print(result["order_status"])
    print("\n=== TRANSACTION LEDGER ===")
    for txn in get_ledger():
        print(txn)


if __name__ == "__main__":
    run_workflow()