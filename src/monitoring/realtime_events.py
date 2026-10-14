import http.server
import json
import queue
import threading
import time
import uuid
from typing import Dict, List, Optional

_global_broker: Optional['AnomalyEventBroker'] = None
_global_server: Optional[http.server.ThreadingHTTPServer] = None
_global_server_port: int = 8502
_server_lock = threading.Lock()

class AnomalyEventBroker:
    """
    Thread-safe broker for publishing, deduplicating, and subscribing to real-time anomaly events.
    Enforces deduplication cooldown to prevent spamming notifications for the same ongoing detection.
    """
    def __init__(self, cooldown_seconds: float = 15.0):
        self.cooldown_seconds = cooldown_seconds
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self._last_emitted: Dict[str, float] = {}
        self._history: List[dict] = []
        self._max_history = 100

    def publish_anomaly(
        self,
        culprit: str,
        severity: str,
        score: float,
        threshold: float,
        confidence: float,
        cpu: float,
        ram: float,
        timestamp: Optional[str] = None,
        description: Optional[str] = None,
        xai: Optional[list] = None,
        anomaly_type: Optional[str] = None
    ) -> Optional[dict]:
        """
        Publishes a new anomaly event to all real-time subscribers if it is not a duplicate.
        Returns the published event dictionary, or None if suppressed by deduplication.
        """
        culprit_clean = (culprit or "Unknown").strip()
        sev_clean = (severity or "CRITICAL").upper()
        dedup_key = f"{culprit_clean.lower()}_{sev_clean}"
        now = time.time()

        with self._lock:
            # Check deduplication window
            last_time = self._last_emitted.get(dedup_key, 0.0)
            if now - last_time < self.cooldown_seconds:
                return None  # Suppress duplicate detection event

            self._last_emitted[dedup_key] = now
            ts_str = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
            event_id = f"anom_{int(now * 1000)}_{uuid.uuid4().hex[:6]}"

            if not anomaly_type:
                anomaly_type = (
                    f"{sev_clean.title()} Resource Anomaly"
                    if cpu < 70
                    else f"Severe CPU & Process Spike"
                )

            if not description:
                description = (
                    f"Process '{culprit_clean}' triggered {sev_clean} anomaly. "
                    f"Sys CPU: {cpu:.1f}%, RAM: {ram:.1f}% (ML Score: {score:.4f} vs threshold: {threshold:.4f})."
                )

            event = {
                "id": event_id,
                "type": anomaly_type,
                "severity": sev_clean,
                "timestamp": ts_str,
                "process": culprit_clean,
                "score": round(float(score), 4),
                "threshold": round(float(threshold), 4),
                "confidence": round(float(confidence), 1),
                "cpu": round(float(cpu), 1),
                "ram": round(float(ram), 1),
                "message": "⚠️ Anomaly Detected! Unusual activity has been identified.",
                "description": description,
                "xai": xai or []
            }

            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)

            # Broadcast to all active subscriber queues
            dead_queues = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead_queues.append(q)

            for dq in dead_queues:
                if dq in self._subscribers:
                    self._subscribers.remove(dq)

            return event

    def subscribe(self) -> queue.Queue:
        """Subscribes a new client queue for receiving real-time events."""
        q = queue.Queue(maxsize=50)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Unsubscribes a client queue."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def get_recent_events(self, limit: int = 10) -> List[dict]:
        with self._lock:
            return list(self._history[-limit:])

    def clear_history(self):
        with self._lock:
            self._history.clear()
            self._last_emitted.clear()


class RealtimeNotificationHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving Server-Sent Events (SSE) and event querying.
    """
    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        clean_path = self.path.split("?")[0]

        if clean_path in ("/api/anomaly-events", "/api/events"):
            self._handle_sse_stream()
        elif clean_path in ("/api/health", "/health"):
            self._handle_health()
        elif clean_path in ("/api/recent-events", "/api/history"):
            self._handle_recent_events()
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"error": "Not found"}')

    def do_POST(self):
        clean_path = self.path.split("?")[0]
        if clean_path in ("/api/publish", "/api/test-event"):
            self._handle_publish()
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Cache-Control")

    def _handle_health(self):
        broker = get_realtime_broker()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        resp = {
            "status": "healthy",
            "active_subscribers": broker.subscriber_count(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def _handle_recent_events(self):
        broker = get_realtime_broker()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        events = broker.get_recent_events(limit=20)
        self.wfile.write(json.dumps(events).encode("utf-8"))

    def _handle_publish(self):
        broker = get_realtime_broker()
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            evt = broker.publish_anomaly(
                culprit=payload.get("process", payload.get("culprit", "test_process.exe")),
                severity=payload.get("severity", "CRITICAL"),
                score=float(payload.get("score", -0.72)),
                threshold=float(payload.get("threshold", -0.60)),
                confidence=float(payload.get("confidence", 92.0)),
                cpu=float(payload.get("cpu", 94.5)),
                ram=float(payload.get("ram", 78.0)),
                timestamp=payload.get("timestamp"),
                description=payload.get("description")
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "event": evt}).encode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def _handle_sse_stream(self):
        broker = get_realtime_broker()
        q = broker.subscribe()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._send_cors_headers()
        self.end_headers()

        # Send initial connected handshake comment
        try:
            self.wfile.write(b": connected to sentinel anomaly event stream\n\n")
            self.wfile.flush()
        except Exception:
            broker.unsubscribe(q)
            return

        try:
            while True:
                try:
                    event = q.get(timeout=8.0)
                    msg = f"data: {json.dumps(event)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Heartbeat comment to prevent client/browser timeout
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, Exception):
            pass
        finally:
            broker.unsubscribe(q)

    def log_message(self, format, *args):
        # Silence default HTTP access logging to preserve clean console
        pass


def get_realtime_broker() -> AnomalyEventBroker:
    """Returns the singleton AnomalyEventBroker."""
    global _global_broker
    if _global_broker is None:
        _global_broker = AnomalyEventBroker()
    return _global_broker


class SentinelHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True


def start_realtime_server(preferred_port: int = 8502, host: str = "127.0.0.1") -> int:
    """
    Starts the real-time SSE daemon server if not already running.
    Returns the active bound port.
    """
    global _global_server, _global_server_port
    with _server_lock:
        if _global_server is not None:
            return _global_server_port

        server = None
        for port_candidate in [preferred_port, 8503, 8504, 8505, 0]:
            try:
                server = SentinelHTTPServer((host, port_candidate), RealtimeNotificationHandler)
                _global_server_port = server.server_address[1]
                break
            except OSError:
                continue

        if server is None:
            raise RuntimeError("Failed to bind RealtimeNotificationServer to any candidate port.")

        _global_server = server
        thread = threading.Thread(target=_global_server.serve_forever, daemon=True, name="Sentinel-SSE-Server")
        thread.start()
        return _global_server_port


def stop_realtime_server():
    """Stops the real-time SSE daemon server."""
    global _global_server
    with _server_lock:
        if _global_server is not None:
            try:
                _global_server.shutdown()
                _global_server.server_close()
            except Exception:
                pass
            _global_server = None


def get_server_port() -> int:
    """Returns the port on which the real-time SSE server is currently bound."""
    global _global_server_port
    return _global_server_port
