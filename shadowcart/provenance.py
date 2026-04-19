# provenance.py
# lightweight defense layer - checks inter-agent message integrity

AUTHORIZED_FIELDS = {
    "search_agent": ["search_results", "session_num"],
    "checkout_agent": ["payment_info", "order_status"]
}

TRUSTED_SELLERS = ["techstore_001", "bestbuy_001", "amazon_001"]

def check_provenance(agent_name: str, state_update: dict) -> dict:
    violations = []

    # field authorization check
    # qn: did this agent write fields it's not supposed to own?
    # attack vector: given the implementation of a multi-agent system, all agents have access
    # to the AgentState, therefore they can access and edit fields. The problem occurs when 
    # a compromised sub-agent changes fields it's not authorized to alter.
    # The field authorization check's purpose is to check if an agent alters fields in AgentState
    # it is not authorized to change
    authorized = AUTHORIZED_FIELDS.get(agent_name, [])
    for field in state_update:
        if field not in authorized:
            violations.append(f"unauthorized field '{field}' written by {agent_name}")

    # seller account integrity
    # qn: is the seller account in the approved list?
    # attack vector: when automating tasks like shopping by using shopping agents, the goal is to help users
    # search the web to find the best products based on price, reviews, shipping costs etc.
    # while searching the web, agents might encounter compromised seller websites or accounts that
    # might compromise the agent by a supply chain attack
    # The seller account integrity aims to ensure that the agents only interact with trusted sellers
    # to protect the shopping agent from encountering malicious sellers
    if "search_results" in state_update:
        seller = state_update["search_results"].get("seller_account")
        if seller and seller not in TRUSTED_SELLERS:
            violations.append(f"unknown seller_account '{seller}' - not in trusted registry")

    # shipping address consistency
    # flag if shipping address changes between sessions
    # attack vector: a supply chain attack or any attack on agents might cause certain constant fields to be altered.
    # for example, a shopping agent would use the same address constantly and if a user changes it, it would be legitimate with 
    # the user's knowledge. But when the address is changed in between sessions (without the user's knowledge) that
    # becomes an issue
    # The shipping address consistency is a placeholder to show how to ensure that certain constant fields
    # are checked for to see if any malicious action has altered them
    if "search_results" in state_update:
        address = state_update["search_results"].get("shipping_address")
        if address and "Attacker" in address:  # in real version this is a baseline comparison
            violations.append(f"shipping address deviation detected: '{address}'")

    return {
        "violations": violations,
        "passed": len(violations) == 0
    }
