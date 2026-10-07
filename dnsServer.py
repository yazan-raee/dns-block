import argparse
import logging
import sqlite3
import time

from dnslib import DNSError, DNSRecord, RCODE
from dnslib.server import BaseResolver, DNSServer


LOGGER = logging.getLogger("dns-blocker")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8053
DEFAULT_UPSTREAM_PORT = 53


def normalize_domain(domain):
    """Return a lowercase, ASCII DNS name without its final dot."""
    domain = domain.strip()
    if domain == ".":
        return "."

    normalized = domain.rstrip(".").encode("idna").decode("ascii").lower()
    if not normalized or len(normalized) > 253:
        raise ValueError("Invalid domain name")

    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("Invalid domain name")
    return normalized


class SQLiteBlocklist:
    """Look up blocked names in a SQLite `blocked_domains(domain)` table."""

    def __init__(self, database_path):
        self.database_path = database_path
        connection = sqlite3.connect(self.database_path)
        try:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS blocked_domains (
                        domain TEXT PRIMARY KEY
                    )
                    """
                )
        finally:
            connection.close()

    def is_blocked(self, domain):
        normalized = normalize_domain(domain)
        if normalized == ".":
            candidates = ["."]
        else:
            labels = normalized.split(".")
            candidates = [".".join(labels[index:]) for index in range(len(labels))]
        placeholders = ", ".join("?" for _ in candidates)

        connection = sqlite3.connect(self.database_path, timeout=2)
        try:
            row = connection.execute(
                "SELECT 1 FROM blocked_domains "
                f"WHERE domain IN ({placeholders}) LIMIT 1",
                candidates,
            ).fetchone()
        finally:
            connection.close()
        return row is not None


class FilteringResolver(BaseResolver):
    def __init__(self, blocklist, upstream_host, upstream_port, timeout):
        self.blocklist = blocklist
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout

    @staticmethod
    def _error_response(request, rcode):
        response = request.reply()
        response.header.ra = 1
        response.header.rcode = rcode
        return response

    def resolve(self, request, handler):
        if len(request.questions) != 1:
            return self._error_response(request, RCODE.FORMERR)

        question = request.questions[0]
        try:
            domain = normalize_domain(str(question.qname))
            blocked = self.blocklist.is_blocked(domain)
        except (ValueError, sqlite3.Error):
            LOGGER.exception("Failed to check the DNS blocklist")
            return self._error_response(request, RCODE.SERVFAIL)

        if blocked:
            response = self._error_response(request, RCODE.NXDOMAIN)
            response.header.aa = 1
            return response

        protocol = getattr(handler, "protocol", "udp")
        try:
            response = request.send(
                self.upstream_host,
                self.upstream_port,
                tcp=protocol == "tcp",
                timeout=self.timeout,
            )
            forwarded = DNSRecord.parse(response)
            if forwarded.header.tc and protocol != "tcp":
                response = request.send(
                    self.upstream_host,
                    self.upstream_port,
                    tcp=True,
                    timeout=self.timeout,
                )
                forwarded = DNSRecord.parse(response)
            forwarded.header.id = request.header.id
            return forwarded
        except (DNSError, OSError, ValueError):
            LOGGER.exception("Failed to forward a DNS query to the upstream resolver")
            return self._error_response(request, RCODE.SERVFAIL)


def positive_integer(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def parse_args():
    parser = argparse.ArgumentParser(description="A SQLite-backed DNS blocker.")
    parser.add_argument("--database", default="blocklist.db", help="SQLite database path")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Address to listen on")
    parser.add_argument("--port", type=positive_integer, default=DEFAULT_PORT)
    parser.add_argument(
        "--upstream",
        required=True,
        help="Upstream DNS server address (for example, 1.1.1.1)",
    )
    parser.add_argument(
        "--upstream-port",
        type=positive_integer,
        default=DEFAULT_UPSTREAM_PORT,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Upstream query timeout in seconds",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.port > 65535 or args.upstream_port > 65535:
        raise SystemExit("Ports must be between 1 and 65535.")
    if args.timeout <= 0:
        raise SystemExit("Timeout must be greater than zero.")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    blocklist = SQLiteBlocklist(args.database)
    resolver = FilteringResolver(
        blocklist,
        args.upstream,
        args.upstream_port,
        args.timeout,
    )

    udp_server = DNSServer(resolver, port=args.port, address=args.host)
    tcp_server = DNSServer(resolver, port=args.port, address=args.host, tcp=True)
    udp_server.start_thread()
    tcp_server.start_thread()
    LOGGER.info("DNS blocker listening on %s:%s (UDP and TCP)", args.host, args.port)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOGGER.info("Stopping DNS blocker")
    finally:
        udp_server.stop()
        tcp_server.stop()


if __name__ == "__main__":
    main()
