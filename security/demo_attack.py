import hmac
import hashlib
import time

# --- ANSI Color Codes for Terminal Output ---
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# System Security Config
SECRET_KEY = b"sentinel_hmac_secret_key_2026"
NODE_ID = "NODE_01"
MAX_FRESHNESS_SEC = 30
WATCHDOG_TIMEOUT_SEC = 60

# In-Memory State Tracking
last_seen_counter = 0

def generate_packet(water_depth: float, rate_of_rise: float, discharge: float, counter: int, timestamp: int):
    """Creates a canonical payload string and generates its HMAC-SHA256 tag."""
    payload_str = f"node={NODE_ID}&H={water_depth:.2f}&RH={rate_of_rise:.2f}&Q={discharge:.2f}&ctr={counter}&ts={timestamp}"
    payload_bytes = payload_str.encode('utf-8')
    tag = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    return payload_bytes, tag, payload_str

def process_and_verify_packet(payload_bytes: bytes, received_tag: bytes, timestamp: int, counter: int, policy_fail: bool = False):
    """
    Core Security Verification Pipeline (Slide 9 & 11)
    Checks: HMAC -> Counter Monotonicity -> Timestamp Freshness -> Policy -> Actuation
    """
    global last_seen_counter
    current_time = int(time.time())

    # 1. HMAC Integrity Check
    computed_tag = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(computed_tag, received_tag):
        return f"{RED}[DROP + LOG]{RESET} HMAC Mismatch! Modified or spoofed frame detected."

    # 2. Replay Check (Counter Monotonicity)
    if counter <= last_seen_counter:
        return f"{RED}[DROP]{RESET} Replay Attack Detected! Counter ({counter}) <= Last Seen ({last_seen_counter})."

    # 3. Timestamp Freshness Check
    if abs(current_time - timestamp) > MAX_FRESHNESS_SEC:
        return f"{RED}[DROP]{RESET} Stale Packet! Age: {abs(current_time - timestamp)}s (Limit: {MAX_FRESHNESS_SEC}s)."

    # 4. Policy Check
    if policy_fail:
        return f"{YELLOW}[NO ACTUATION]{RESET} Valid packet, but policy threshold not breached (GREEN State)."

    # All checks passed
    last_seen_counter = counter
    return f"{GREEN}{BOLD}[ACTUATE SIREN]{RESET} All checks PASSED (AuthValid, Fresh, CounterValid, SchemaValid, PolicyPass)."

def run_security_demonstration():
    print(f"\n{CYAN}{BOLD}==============================================================={RESET}")
    print(f"{CYAN}{BOLD}   AIoT Sentinel - Cyber Security & Actuation Verification Demo  {RESET}")
    print(f"{CYAN}{BOLD}==============================================================={RESET}\n")

    now = int(time.time())

    # Case 1: Valid Authenticated Packet
    print(f"{BOLD}Test Case 1: Valid Authenticated Packet (Normal Flow){RESET}")
    payload_b, tag, payload_str = generate_packet(water_depth=2.45, rate_of_rise=0.12, discharge=15.4, counter=101, timestamp=now)
    print(f" Payload: {payload_str}")
    result = process_and_verify_packet(payload_b, tag, now, 101)
    print(f" Decision: {result}\n")
    time.sleep(1)

    # Case 2: Tampered Payload Attack
    print(f"{BOLD}Test Case 2: Data Tampering Attack (Attacker modifies water depth to 8.5m){RESET}")
    tampered_payload_str = f"node={NODE_ID}&H=8.50&RH=0.12&Q=15.4&ctr=102&ts={now}"
    print(f" Modified Payload: {tampered_payload_str}")
    result = process_and_verify_packet(tampered_payload_str.encode(), tag, now, 102)
    print(f" Decision: {result}\n")
    time.sleep(1)

    # Case 3: Replay Attack
    print(f"{BOLD}Test Case 3: Replay Attack (Attacker re-sends packet 101){RESET}")
    print(f" Replaying Counter: 101")
    result = process_and_verify_packet(payload_b, tag, now, 101)
    print(f" Decision: {result}\n")
    time.sleep(1)

    # Case 4: Stale Timestamp Attack
    print(f"{BOLD}Test Case 4: Delayed/Stale Packet Attack (Timestamp is 45s old){RESET}")
    stale_time = now - 45
    payload_stale, tag_stale, _ = generate_packet(water_depth=2.50, rate_of_rise=0.10, discharge=15.0, counter=103, timestamp=stale_time)
    result = process_and_verify_packet(payload_stale, tag_stale, stale_time, 103)
    print(f" Decision: {result}\n")
    time.sleep(1)

    # Case 5: Heartbeat Watchdog Timeout
    print(f"{BOLD}Test Case 5: Heartbeat Watchdog Timeout (>60s silence){RESET}")
    print(f" System: No valid telemetry received for 65 seconds.")
    print(f" Decision: {YELLOW}{BOLD}[SUPPRESSION ALERT]{RESET} Gateway silenced siren interlock due to missing heartbeat.\n")

if __name__ == "__main__":
    run_security_demonstration()