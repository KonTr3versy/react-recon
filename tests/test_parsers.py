import json

from react_recon.parsers import parse_alterx, parse_crtsh, parse_dnsx, parse_gau, parse_httpx, parse_naabu, parse_nmap, parse_subfinder


def test_subfinder_normalizes_and_deduplicates_hosts():
    output = "App.EXAMPLE.com.\napp.example.com\nnot a host\n"
    assert parse_subfinder(output) == [{"type": "hostname", "value": "app.example.com", "source": None}]


def test_dnsx_parses_json_record_arrays():
    output = json.dumps({"host": "app.example.com", "a": ["192.0.2.10"], "mx": ["mail.example.com"]})
    assert {item["type"] for item in parse_dnsx(output)} == {"dns_a", "dns_mx"}


def test_dnsx_retains_resolution_enrichment_without_promoting_empty_records():
    output = "\n".join(
        [
            '{"host":"app.example.com","a":["192.0.2.4"],"cname":["edge.example.net"],"cdn-name":"cloudflare","cdn-type":"waf","asn":["AS13335"],"status_code":"NOERROR"}',
            '{"host":"missing.example.com","status_code":"NXDOMAIN","asn":["AS64500"]}',
        ]
    )
    observations = parse_dnsx(output)
    assert {item["type"] for item in observations} == {"dns_a", "dns_cname", "dns_cdn", "dns_asn", "dns_status"}
    assert all(item["host"] == "app.example.com" for item in observations)


def test_alterx_normalizes_deduplicates_and_rejects_malformed_candidates():
    assert parse_alterx("Dev.Example.com.\ndev.example.com\nnot a host\n") == [
        {"type": "permutation_candidate", "value": "dev.example.com", "generator": "alterx"}
    ]


def test_httpx_and_naabu_handle_structured_and_plain_output():
    assert parse_httpx('{"url":"https://app.example.com","status-code":200}')[0]["type"] == "http_service"
    assert parse_naabu("app.example.com:443\napp.example.com:443\n")[0]["port"] == 443


def test_httpx_failures_and_gau_json_are_not_misclassified():
    failed = parse_httpx('{"input":"offline.example.com","failed":true,"error":"dial timeout"}\n')[0]
    assert failed["type"] == "http_probe_failure"
    assert parse_gau('{"url":"https://www.example.com/admin/login"}\n')[0]["value"] == "https://www.example.com/admin/login"


def test_naabu_json_and_nmap_xml_are_normalized():
    naabu = parse_naabu('{"host":"vpn.example.com","ip":"192.0.2.4","port":8443,"protocol":"tcp","tls":true}\n')
    assert naabu == [{"type": "open_port", "host": "vpn.example.com", "port": 8443, "protocol": "tcp", "ip": "192.0.2.4", "tls": True}]
    nmap_xml = """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.4'/><hostnames><hostname name='vpn.example.com'/></hostnames><ports><port protocol='tcp' portid='8443'><state state='open'/><service name='https-alt' product='Example Gateway' version='1.2'><cpe>cpe:/a:example:gateway:1.2</cpe></service></port></ports></host></nmaprun>"""
    service = parse_nmap(nmap_xml)[0]
    assert service["host"] == "vpn.example.com"
    assert service["product"] == "Example Gateway"
    assert service["cpe"] == "cpe:/a:example:gateway:1.2"


def test_crtsh_extracts_and_normalizes_sans():
    output = json.dumps([{"id": 1, "name_value": "*.Example.com\napi.example.com", "common_name": "*.example.com", "issuer_name": "Test CA"}])
    results = parse_crtsh(output)
    assert {item["value"] for item in results} == {"example.com", "api.example.com"}
