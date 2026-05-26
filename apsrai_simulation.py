import json
import csv
import random
import argparse
from uuid import uuid4
from datetime import datetime

NODES = ["node-01", "node-03", "node-07", "node-11", "node-14"]
EVENT_TYPES = ["cpu_spike", "network_flood", "auth_failure", "latency_breach", "disk_overflow"]

def generate_synthetic_log(n=15):
    entries = []
    for _ in range(n):
        policy_limit = round(random.uniform(0.5, 0.8), 2)
        # ~65% chance of exceeding limit
        observed = round(random.uniform(0.3, 1.2), 2)
        entries.append({
            "entry_id": str(uuid4()),
            "node": random.choice(NODES),
            "event_type": random.choice(EVENT_TYPES),
            "observed_value": observed,
            "policy_limit": policy_limit
        })
    return entries

# --- Detection ---

def detect_anomaly(entry):
    if entry["observed_value"] <= entry["policy_limit"]:
        return None
    confidence = round(
        min((entry["observed_value"] / entry["policy_limit"]) - 1.0, 1.0), 2
    )
    return {
        "entry_id": entry["entry_id"],
        "node": entry["node"],
        "anomaly_type": entry["event_type"],
        "observed_value": entry["observed_value"],
        "policy_limit": entry["policy_limit"],
        "confidence": confidence
    }
# --- Alert Generation ---

def generate_alert(anomaly):
    return {
        "alert_id": str(uuid4()),
        "alert_timestamp": datetime.now().isoformat(),
        "anomaly_type": anomaly["anomaly_type"],
        "confidence": anomaly["confidence"],
        "policy_limit": anomaly["policy_limit"],
        "node": anomaly["node"]
    }
# --- Human Decision (Mandatory Halt) ---

DECISION_MAP = {
    "1": "threat_confirmed",
    "2": "false_positive",
    "3": "escalated"
}

def human_decision(alert, simulate=False):
    print("\n" + "="*50)
    print("MANDATORY SYSTEM HALT — Human Decision Required")
    print("="*50)
    print(f"  Node          : {alert['node']}")
    print(f"  Anomaly Type  : {alert['anomaly_type']}")
    print(f"  Confidence    : {alert['confidence']}")
    print(f"  Policy Limit  : {alert['policy_limit']}")
    print(f"  Alert ID      : {alert['alert_id']}")
    print("-"*50)

    if simulate:
        choice = random.choices(["1", "2", "3"], weights=[30, 50, 20])[0]
        print(f"  [SIMULATED] Operator response: {choice} → {DECISION_MAP[choice]}")
        return DECISION_MAP[choice]

    while True:
        response = input("  Decision — 1: Confirm Threat | 2: False Positive | 3: Escalate : ").strip()
        if response in DECISION_MAP:
            return DECISION_MAP[response]
        print("  Invalid input. Enter 1, 2, or 3 only.")

# --- Audit Log ---

def write_audit_log(alert, decision, filepath="apsrai_audit_log.jsonl"):
    record = {
        "log_id": str(uuid4()),
        "alert_id": alert["alert_id"],
        "alert_timestamp": alert["alert_timestamp"],
        "node": alert["node"],
        "anomaly_type": alert["anomaly_type"],
        "confidence": alert["confidence"],
        "policy_limit": alert["policy_limit"],
        "operator_decision": decision,
        "log_timestamp": datetime.now().isoformat()
    }
    with open(filepath, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record

# --- Summary CSV ---

def write_summary_csv(records, filepath="apsrai_summary.csv"):
    fields = [
        "log_id", "node", "anomaly_type", "confidence",
        "policy_limit", "operator_decision", "log_timestamp"
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


# --- Main ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APSRAI Simulation")
    parser.add_argument("--simulate", action="store_true",
                        help="Run unattended with randomized operator decisions")
    args = parser.parse_args()

    log_entries = generate_synthetic_log(15)
    audit_records = []
    anomaly_count = 0

    for entry in log_entries:
        anomaly = detect_anomaly(entry)
        if anomaly is None:
            continue
        anomaly_count += 1
        alert = generate_alert(anomaly)
        decision = human_decision(alert, simulate=args.simulate)
        record = write_audit_log(alert, decision)
        audit_records.append(record)

    write_summary_csv(audit_records)

    print("\n" + "="*50)
    print(f"  Entries processed : {len(log_entries)}")
    print(f"  Anomalies detected: {anomaly_count}")
    print(f"  Decisions logged  : {len(audit_records)}")
    print(f"  Audit log         : apsrai_audit_log.jsonl")
    print(f"  Summary CSV       : apsrai_summary.csv")
    print("="*50)