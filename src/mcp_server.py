import json
import logging
import re
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import Config
from .database import Database
from .nvd import CVEParser, NVDClient

log = logging.getLogger("vulnwatch.mcp")


class MCPRequestHandler(BaseHTTPRequestHandler):
    """Handles MCP (Model Context Protocol) JSON-RPC over HTTP and REST endpoints."""

    def __init__(self, request, client_address, server):
        self.mcp: MCPServer = server.mcp_instance
        super().__init__(request, client_address, server)

    def log_message(self, format: str, *args: Any) -> None:
        log.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-MCP-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def _check_auth(self) -> bool:
        """Validate Bearer token, X-MCP-Token header, or URL query token."""
        expected_token = self.mcp.config.mcp_auth_token
        if not expected_token:
            return True

        # Check Authorization: Bearer <TOKEN>
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip().strip("'\"")
            if token == expected_token:
                return True

        # Check X-MCP-Token header
        custom_header = self.headers.get("X-MCP-Token", "").strip().strip("'\"")
        if custom_header == expected_token:
            return True

        # Check query string (?token=...)
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if "token" in query and query["token"][0].strip().strip("'\"") == expected_token:
            return True

        return False

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-MCP-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Healthcheck endpoint (open to container health monitors)
        if path in ("", "/health", "/status"):
            stats = self.mcp.db.get_stats()
            self._send_json(200, {
                "status": "online",
                "service": "VulnWatch MCP Server",
                "version": "1.0.0",
                "mcp_protocol": "2024-11-05",
                "stats": stats,
            })
            return

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized: Invalid or missing MCP authentication token"})
            return

        if path == "/tools":
            self._send_json(200, {"tools": self.mcp.get_tool_definitions()})
            return

        if path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            event_data = f"event: endpoint\ndata: /mcp\n\n".encode("utf-8")
            self.wfile.write(event_data)
            return

        self._send_json(404, {"error": f"Endpoint {self.path} not found"})

    def do_POST(self) -> None:
        if not self._check_auth():
            self._send_json(401, {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "Unauthorized: Invalid or missing MCP token"
                }
            })
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send_json(400, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Empty request body"}})
            return

        body = self.rfile.read(content_length)
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception as exc:
            self._send_json(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": f"Parse error: {exc}"}})
            return

        response = self.mcp.handle_jsonrpc(req)
        if response is not None:
            self._send_json(200, response)
        else:
            self.send_response(204)
            self.end_headers()


class MCPServer:
    """
    Model Context Protocol (MCP) Server for VulnWatch.
    Allows AI agents and tools to query vulnerability data and perform CVE intelligence lookups.
    """

    def __init__(
        self,
        config: Config,
        database: Database,
        nvd_client: NVDClient,
        service: Any = None,
    ):
        self.config = config
        self.db = database
        self.nvd = nvd_client
        self.service = service
        self.httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False

    def start_in_background(self) -> None:
        """Start the MCP HTTP server in a background thread."""
        host = self.config.mcp_host
        port = self.config.mcp_port

        class CustomServer(ThreadingHTTPServer):
            mcp_instance = self

        self.httpd = CustomServer((host, port), MCPRequestHandler)
        self.running = True
        self._thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="MCPServerThread",
            daemon=True,
        )
        self._thread.start()
        log.info("MCP Server started at http://%s:%d (URL: %s)", host, port, self.config.mcp_url)

    def stop(self) -> None:
        """Shutdown the MCP HTTP server."""
        if self.httpd:
            self.running = False
            self.httpd.shutdown()
            self.httpd.server_close()
            log.info("MCP Server stopped.")

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool schemas available to AI models."""
        return [
            {
                "name": "search_cves_by_date",
                "description": "Search CVE vulnerabilities published on a specific date (format: YYYY-MM-DD). Checks local DB and queries NIST NVD API.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "date": {
                            "type": "string",
                            "description": "Publication date in YYYY-MM-DD format, e.g. '2026-10-24'"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of CVEs to return (default: 10)"
                        }
                    },
                    "required": ["date"]
                }
            },
            {
                "name": "get_cve_details",
                "description": "Retrieve comprehensive vulnerability intelligence for a CVE identifier (CVSS, severity, affected products, CWE, CISA KEV exploitation, references).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": "The CVE identifier, e.g. 'CVE-2026-115929'"
                        }
                    },
                    "required": ["cve_id"]
                }
            },
            {
                "name": "get_latest_vulnerabilities",
                "description": "Fetch the most recently indexed or published vulnerabilities from VulnWatch.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Number of vulnerabilities to retrieve (default: 5)"
                        }
                    }
                }
            },
            {
                "name": "get_cisa_kev_catalog",
                "description": "Query the CISA Known Exploited Vulnerabilities catalog for actively targeted in-the-wild CVEs and ransomware associations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum entries to return (default: 10)"
                        },
                        "ransomware_only": {
                            "type": "boolean",
                            "description": "Filter strictly for vulnerabilities known to be used in ransomware attacks"
                        }
                    }
                }
            },
            {
                "name": "get_vulnwatch_status",
                "description": "Retrieve VulnWatch system health, sync timestamps, database counts, and monitoring configuration.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "get_watchlist",
                "description": "Get all technologies, frameworks, and programs currently monitored in the VulnWatch watchlist.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "add_to_watchlist",
                "description": "Add a software program or framework keyword to the monitored watchlist (e.g. 'php', 'laravel').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "keyword": {
                            "type": "string",
                            "description": "Name of the technology, program, or framework (e.g. 'php', 'laravel', 'wordpress')"
                        }
                    },
                    "required": ["keyword"]
                }
            },
            {
                "name": "remove_from_watchlist",
                "description": "Remove a software program or framework keyword from the monitored watchlist.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "keyword": {
                            "type": "string",
                            "description": "Name of the technology to remove"
                        }
                    },
                    "required": ["keyword"]
                }
            },
            {
                "name": "clear_watchlist",
                "description": "Clear all items from the monitored watchlist (reverts to monitoring all technologies).",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "get_vulnerabilities_by_severity",
                "description": "Fetch the most recent vulnerabilities filtered by severity (CRITICAL, HIGH, MEDIUM, LOW).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                            "description": "Severity level to filter by"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of CVEs to return (default: 5)"
                        }
                    },
                    "required": ["severity"]
                }
            },
            {
                "name": "set_rating_filter",
                "description": "Set the alert severity threshold filter ('critical', 'high', 'medium', 'all').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rating": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "all"],
                            "description": "Severity threshold for alerts"
                        }
                    },
                    "required": ["rating"]
                }
            },
            {
                "name": "get_settings",
                "description": "Retrieve all active configuration settings, threshold overrides, and monitored technology watchlist.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "set_setting",
                "description": "Update a runtime setting on the fly ('min_cvss', 'poll_seconds', 'max_cve_age_days', 'rating').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key": {
                            "type": "string",
                            "description": "Setting key to change (e.g. 'min_cvss', 'poll_seconds', 'max_cve_age_days', 'rating')"
                        },
                        "value": {
                            "type": "string",
                            "description": "New value for the setting"
                        }
                    },
                    "required": ["key", "value"]
                }
            },
            {
                "name": "trigger_sync",
                "description": "Trigger an immediate vulnerability synchronization cycle in the background.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_jsonrpc(self, req: dict[str, Any]) -> dict[str, Any] | None:
        """Process incoming MCP JSON-RPC 2.0 messages."""
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        # Handle notifications (no response needed)
        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                    },
                    "serverInfo": {
                        "name": "vulnwatch-mcp",
                        "version": "1.0.0"
                    }
                }
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.get_tool_definitions()}
            }

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments") or {}
            result = self._execute_tool(tool_name, args)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [
                        {
                            "uri": "vulnwatch://status",
                            "name": "VulnWatch Status",
                            "mimeType": "application/json",
                            "description": "System health and sync cursor status"
                        },
                        {
                            "uri": "vulnwatch://cves/latest",
                            "name": "Latest Vulnerabilities",
                            "mimeType": "application/json",
                            "description": "Most recently published CVEs"
                        },
                        {
                            "uri": "vulnwatch://kev",
                            "name": "CISA KEV Catalog",
                            "mimeType": "application/json",
                            "description": "Known Exploited Vulnerabilities"
                        }
                    ]
                }
            }

        if method == "resources/read":
            uri = params.get("uri", "")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": [self._read_resource(uri)]
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }

    def _execute_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch tool execution and return MCP content block."""
        try:
            if name == "search_cves_by_date":
                date_str = str(args.get("date", "")).strip()
                limit = max(1, min(50, int(args.get("limit", 10))))

                if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": "Invalid date format. Expected YYYY-MM-DD (e.g. '2026-10-24')"}]
                    }

                rows = self.db.search_by_date(date_str, limit=limit)
                if not rows:
                    # Query NVD directly if not in local DB
                    start_dt = datetime.fromisoformat(f"{date_str}T00:00:00+00:00")
                    end_dt = datetime.fromisoformat(f"{date_str}T23:59:59+00:00")
                    cves = self.nvd.fetch_cves(start=start_dt, end=end_dt, only_newly_published=True)
                    for cve in cves:
                        cve_id = cve.get("id")
                        if cve_id:
                            score, sev = CVEParser.extract_cvss(cve)
                            self.db.save_cve_data(
                                cve_id=cve_id,
                                published=cve.get("published"),
                                modified=cve.get("lastModified"),
                                description=CVEParser.extract_description(cve),
                                cvss=score,
                                severity=sev,
                                products=CVEParser.extract_products(cve),
                                cwe=CVEParser.extract_cwes(cve),
                                refs=CVEParser.extract_refs(cve),
                            )
                    rows = self.db.search_by_date(date_str, limit=limit)

                items = [dict(r) for r in rows]
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"date": date_str, "count": len(items), "cves": items}, indent=2)}]
                }

            elif name == "get_cve_details":
                cve_id = str(args.get("cve_id", "")).strip().upper()
                row = self.db.get_vulnerability(cve_id)
                if not row:
                    cve_data = self.nvd.fetch_cve_by_id(cve_id)
                    if cve_data:
                        score, sev = CVEParser.extract_cvss(cve_data)
                        self.db.save_cve_data(
                            cve_id=cve_id,
                            published=cve_data.get("published"),
                            modified=cve_data.get("lastModified"),
                            description=CVEParser.extract_description(cve_data),
                            cvss=score,
                            severity=sev,
                            products=CVEParser.extract_products(cve_data),
                            cwe=CVEParser.extract_cwes(cve_data),
                            refs=CVEParser.extract_refs(cve_data),
                        )
                        row = self.db.get_vulnerability(cve_id)

                if not row:
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": f"CVE '{cve_id}' not found in database or NVD."}]
                    }

                data = dict(row)
                try:
                    data["refs"] = json.loads(data["refs"] or "[]")
                except Exception:
                    pass

                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps(data, indent=2)}]
                }

            elif name == "get_latest_vulnerabilities":
                limit = max(1, min(50, int(args.get("limit", 5))))
                rows = self.db.get_latest_vulnerabilities(limit=limit)
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"count": len(rows), "cves": [dict(r) for r in rows]}, indent=2)}]
                }

            elif name == "get_cisa_kev_catalog":
                limit = max(1, min(100, int(args.get("limit", 10))))
                ransomware_only = bool(args.get("ransomware_only", False))
                rows = self.db.get_latest_kev(limit=limit)
                items = [dict(r) for r in rows]
                if ransomware_only:
                    items = [it for it in items if it.get("ransomware") and it["ransomware"].lower() == "known"]
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"count": len(items), "kev_entries": items}, indent=2)}]
                }

            elif name == "get_vulnwatch_status":
                stats = self.db.get_stats()
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({
                        "app": self.config.app_name,
                        "poll_seconds": self.config.poll_seconds,
                        "min_cvss": self.config.min_cvss,
                        "only_high_or_kev": self.config.only_high_or_kev,
                        "only_newly_published": self.config.only_newly_published,
                        "start_from_now": self.config.start_from_now,
                        "watchlist": self.db.get_watchlist(),
                        "stats": stats,
                    }, indent=2)}]
                }

            elif name == "get_watchlist":
                items = self.db.get_watchlist()
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"count": len(items), "watchlist": items}, indent=2)}]
                }

            elif name == "add_to_watchlist":
                keyword = str(args.get("keyword", "")).strip().lower()
                if not keyword:
                    return {"isError": True, "content": [{"type": "text", "text": "Keyword is required."}]}
                added = self.db.add_to_watchlist(keyword)
                items = self.db.get_watchlist()
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"added": added, "keyword": keyword, "watchlist": items}, indent=2)}]
                }

            elif name == "remove_from_watchlist":
                keyword = str(args.get("keyword", "")).strip().lower()
                removed = self.db.remove_from_watchlist(keyword)
                items = self.db.get_watchlist()
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"removed": removed, "keyword": keyword, "watchlist": items}, indent=2)}]
                }

            elif name == "clear_watchlist":
                count = self.db.clear_watchlist()
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"cleared": True, "removed_count": count, "watchlist": []}, indent=2)}]
                }

            elif name == "get_vulnerabilities_by_severity":
                severity = str(args.get("severity", "")).strip().upper()
                limit = max(1, min(50, int(args.get("limit", 5))))
                rows = self.db.get_vulnerabilities_by_severity(severity, limit=limit)
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"severity": severity, "count": len(rows), "cves": [dict(r) for r in rows]}, indent=2)}]
                }

            elif name == "set_rating_filter":
                rating = str(args.get("rating", "")).strip().lower()
                valid = {
                    "critical": 9.0,
                    "high": 7.0,
                    "medium": 4.0,
                    "all": 0.0,
                }
                if rating not in valid:
                    return {"isError": True, "content": [{"type": "text", "text": f"Invalid rating '{rating}'. Must be one of: {list(valid.keys())}"}]}

                self.db.set_state("setting_rating_filter", rating)
                self.db.set_state("setting_min_cvss", str(valid[rating]))
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"rating": rating, "min_cvss": valid[rating], "status": "updated"}, indent=2)}]
                }

            elif name == "get_settings":
                active_rating = (self.db.get_state("setting_rating_filter") or "high" if self.config.only_high_or_kev else "all").upper()
                min_cvss = self.db.get_state("setting_min_cvss") or str(self.config.min_cvss)
                poll_sec = self.db.get_state("setting_poll_seconds") or str(self.config.poll_seconds)
                max_age = self.db.get_state("setting_max_cve_age_days") or str(self.config.max_cve_age_days)
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({
                        "app_name": self.config.app_name,
                        "rating_filter": active_rating,
                        "min_cvss": float(min_cvss),
                        "poll_seconds": int(poll_sec),
                        "max_cve_age_days": int(max_age),
                        "watchlist": self.db.get_watchlist(),
                        "start_from_now": self.config.start_from_now,
                        "only_newly_published": self.config.only_newly_published,
                        "telegram_enabled": self.config.telegram_bot_enabled,
                        "mcp_enabled": self.config.mcp_enabled,
                    }, indent=2)}]
                }

            elif name == "set_setting":
                key = str(args.get("key", "")).strip().lower()
                val = str(args.get("value", "")).strip()

                if key in ("cvss", "min_cvss"):
                    score = float(val)
                    self.db.set_state("setting_min_cvss", str(score))
                    res_text = f"Updated min_cvss to {score}"
                elif key in ("poll", "poll_seconds"):
                    sec = max(60, int(val))
                    self.db.set_state("setting_poll_seconds", str(sec))
                    res_text = f"Updated poll_seconds to {sec}"
                elif key in ("age", "max_age", "max_cve_age_days"):
                    days = max(0, int(val))
                    self.db.set_state("setting_max_cve_age_days", str(days))
                    res_text = f"Updated max_cve_age_days to {days}"
                elif key in ("rating", "filter"):
                    self.db.set_state("setting_rating_filter", val.lower())
                    res_text = f"Updated rating_filter to {val.lower()}"
                else:
                    return {"isError": True, "content": [{"type": "text", "text": f"Unsupported setting key '{key}'."}]}

                return {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps({"status": "success", "message": res_text}, indent=2)}]
                }

            elif name == "trigger_sync":
                if self.service:
                    threading.Thread(target=self.service.run_cycle, daemon=True).start()
                    return {
                        "isError": False,
                        "content": [{"type": "text", "text": json.dumps({"status": "initiated", "message": "Background sync cycle started."}, indent=2)}]
                    }
                else:
                    return {"isError": True, "content": [{"type": "text", "text": "Sync service not attached to MCP server."}]}

            else:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool: '{name}'"}]
                }

        except Exception as exc:
            log.exception("Error executing tool %s: %s", name, exc)
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Tool execution failed: {exc}"}]
            }

    def _read_resource(self, uri: str) -> dict[str, Any]:
        """Read resource content by URI."""
        if uri == "vulnwatch://status":
            stats = self.db.get_stats()
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(stats, indent=2)}
        elif uri == "vulnwatch://cves/latest":
            rows = [dict(r) for r in self.db.get_latest_vulnerabilities(limit=5)]
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(rows, indent=2)}
        elif uri == "vulnwatch://kev":
            rows = [dict(r) for r in self.db.get_latest_kev(limit=5)]
            return {"uri": uri, "mimeType": "application/json", "text": json.dumps(rows, indent=2)}
        else:
            return {"uri": uri, "mimeType": "text/plain", "text": f"Resource {uri} not found"}
