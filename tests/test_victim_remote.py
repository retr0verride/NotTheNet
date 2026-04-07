"""Tests for victim IP discovery helpers."""

from utils.victim_remote import _parse_ip_neigh_output


def test_parse_ip_neigh_with_dev_token():
    out = "10.10.10.10 dev eth1 lladdr 08:00:27:aa:bb:cc REACHABLE\n"
    hosts = _parse_ip_neigh_output(out, bind_ip="10.10.10.1")

    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.10"
    assert hosts[0].mac == "08:00:27:aa:bb:cc"


def test_parse_ip_neigh_without_dev_token():
    out = "10.10.10.11 lladdr 08:00:27:aa:bb:dd STALE\n"
    hosts = _parse_ip_neigh_output(out, bind_ip="10.10.10.1")

    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.11"
    assert hosts[0].mac == "08:00:27:aa:bb:dd"


def test_parse_ip_neigh_skips_bind_incomplete_and_ipv6():
    out = "\n".join(
        [
            "10.10.10.1 lladdr 08:00:27:00:00:01 REACHABLE",
            "10.10.10.15 dev eth1 INCOMPLETE",
            "fe80::1 dev eth1 lladdr 00:11:22:33:44:55 REACHABLE",
            "10.10.10.20 dev eth1 lladdr 08:00:27:aa:bb:ee DELAY",
        ]
    )
    hosts = _parse_ip_neigh_output(out, bind_ip="10.10.10.1")

    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.20"
