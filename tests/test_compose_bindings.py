from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_compose_uses_explicit_container_addresses_and_loopback_host_ports() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    backend = compose["services"]["sentinellogs"]
    nginx = compose["services"]["nginx"]

    assert any(
        "${SENTINELLOGS_BACKEND_CONTAINER_ADDRESS" in argument
        for argument in backend["command"]
    )
    assert backend["networks"]["default"]["ipv4_address"].startswith("${SENTINELLOGS_BACKEND_CONTAINER_ADDRESS")
    assert nginx["ports"] == ["127.0.0.1:80:80", "127.0.0.1:443:443"]
    assert nginx["networks"]["default"]["ipv4_address"].startswith("${SENTINELLOGS_NGINX_CONTAINER_ADDRESS")
    assert nginx["entrypoint"] == ["/bin/sh", "/sentinellogs-nginx-entrypoint.sh"]


def test_nginx_configuration_renders_explicit_listen_addresses() -> None:
    config = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    entrypoint = (ROOT / "nginx" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "listen @SENTINELLOGS_NGINX_BIND_ADDRESS@:80;" in config
    assert "listen @SENTINELLOGS_NGINX_BIND_ADDRESS@:443 ssl;" in config
    assert "listen 80;" not in config
    assert "listen 443 ssl;" not in config
    assert "exec nginx -c /tmp/sentinellogs-nginx.conf" in entrypoint
