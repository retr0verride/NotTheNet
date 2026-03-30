#!/usr/bin/env python3
"""Quick test of python-iptables UDP match creation."""
import iptc
import ctypes as ct

# Test TCP match
print("--- TCP test ---")
r = iptc.Rule()
r.protocol = "tcp"
m = r.create_match("tcp")
m.dport = "53"
print(f"TCP dport: {m.dport}")

# Test UDP match — approach 1: parameters dict
print("--- UDP test (approach 1: parameters) ---")
try:
    r2 = iptc.Rule()
    r2.protocol = "udp"
    m2 = r2.create_match("udp")
    m2.dport = "53"
    print(f"  approach 1 OK: {m2.dport}")
except Exception as e:
    print(f"  approach 1 failed: {e}")

# Test UDP match — approach 2: set_parameter
print("--- UDP test (approach 2: set_parameter) ---")
try:
    r3 = iptc.Rule()
    r3.protocol = "udp"
    m3 = r3.create_match("udp")
    m3.set_parameter("dport", "53")
    print(f"  approach 2 OK")
except Exception as e:
    print(f"  approach 2 failed: {e}")

# Test UDP match — approach 3: use _parse directly
print("--- UDP test (approach 3: _parse) ---")
try:
    r4 = iptc.Rule()
    r4.protocol = "udp"
    m4 = r4.create_match("udp")
    # Check what parameters are available
    print(f"  match name: {m4.name}")
    print(f"  dir(m4): {[x for x in dir(m4) if not x.startswith('_')]}")
except Exception as e:
    print(f"  approach 3 failed: {e}")

# Test UDP match — approach 4: subprocess fallback
print("--- UDP test (approach 4: subprocess) ---")
import subprocess
result = subprocess.run(
    ["iptables", "-t", "nat", "-A", "PREROUTING",
     "-i", "eth0", "-p", "udp", "--dport", "53",
     "-j", "DNAT", "--to-destination", "127.0.0.1:50053",
     "-m", "comment", "--comment", "IPTC_TEST_DELETE_ME"],
    capture_output=True, text=True, timeout=5
)
if result.returncode == 0:
    print("  approach 4 OK (subprocess iptables)")
else:
    print(f"  approach 4 failed: {result.stderr}")

# Cleanup
subprocess.run(
    ["iptables", "-t", "nat", "-D", "PREROUTING",
     "-i", "eth0", "-p", "udp", "--dport", "53",
     "-j", "DNAT", "--to-destination", "127.0.0.1:50053",
     "-m", "comment", "--comment", "IPTC_TEST_DELETE_ME"],
    capture_output=True, text=True, timeout=5
)
print("  cleanup done")

# Test full DNAT rule insertion + cleanup
print("--- Full DNAT rule test ---")
table = iptc.Table(iptc.Table.NAT)
chain = iptc.Chain(table, "PREROUTING")

rule = iptc.Rule()
rule.protocol = "udp"
rule.in_interface = "eth0"

match = rule.create_match("udp")
match.dport = "53"

comment = rule.create_match("comment")
comment.comment = "IPTC_TEST_DELETE_ME"

target = rule.create_target("DNAT")
target.to_destination = "127.0.0.1:50053"

chain.insert_rule(rule)
print("Rule inserted OK")

# Now delete it
table.refresh()
for r in list(chain.rules):
    for m in r.matches:
        if hasattr(m, "comment") and m.comment == "IPTC_TEST_DELETE_ME":
            chain.delete_rule(r)
            print("Rule deleted OK")
            break

print("ALL TESTS PASSED")
