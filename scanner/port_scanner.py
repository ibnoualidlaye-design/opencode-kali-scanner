import socket
import threading
from queue import Queue
from scanner.banner_grab import grab_banner_tcp, grab_banner_udp

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1000, timeout=0.5, threads=80, protocol="tcp", debug=False):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.protocol = protocol
        self.debug = debug
        self.results = []
        self.queue = Queue()
        
        if self.debug:
            print(f"[DEBUG] Scanner initialized:")
            print(f"  Target: {self.target}")
            print(f"  Port range: {self.start_port}-{self.end_port}")
            print(f"  Timeout: {self.timeout}s")
            print(f"  Threads: {self.threads}")
            print(f"  Protocol: {self.protocol}")

    def detect_service(self, port):
        services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 135: "RPC",
            139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 3306: "MYSQL",
            5432: "POSTGRESQL", 8000: "HTTP", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
        }
        return services.get(port, "UNKNOWN")

    def scan_tcp_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if self.debug:
                print(f"[DEBUG] Testing TCP port {port}...")
            
            sock.connect((self.target, port))
            
            if self.debug:
                print(f"[DEBUG] TCP port {port} -> OPEN")
            
            banner = grab_banner_tcp(self.target, port, self.timeout)
            service = self.detect_service(port)
            
            self.results.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "banner": banner,
            })
            
            if self.debug:
                print(f"[DEBUG] Added result: port {port}, service {service}, banner: {banner or 'NONE'}")
        
        except socket.timeout:
            if self.debug:
                print(f"[DEBUG] TCP port {port} -> TIMEOUT")
        except ConnectionRefusedError:
            if self.debug:
                print(f"[DEBUG] TCP port {port} -> CLOSED (Connection refused)")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] TCP port {port} -> ERROR: {type(e).__name__}: {e}")
        finally:
            sock.close()

    def scan_udp_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            if self.debug:
                print(f"[DEBUG] Testing UDP port {port}...")
            
            sock.sendto(b"", (self.target, port))
            data, _ = sock.recvfrom(1024)
            
            if self.debug:
                print(f"[DEBUG] UDP port {port} -> OPEN")
            
            banner = data.decode("utf-8", errors="replace").strip()
            service = self.detect_service(port)
            
            self.results.append({
                "port": port,
                "protocol": "udp",
                "state": "open",
                "service": service,
                "banner": banner,
            })
            
            if self.debug:
                print(f"[DEBUG] Added result: port {port}, service {service}, banner: {banner or 'NONE'}")
        
        except socket.timeout:
            if self.debug:
                print(f"[DEBUG] UDP port {port} -> TIMEOUT")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] UDP port {port} -> ERROR: {type(e).__name__}: {e}")
        finally:
            sock.close()

    def worker(self):
        while True:
            port = self.queue.get()
            if port is None:
                if self.debug:
                    print(f"[DEBUG] Worker thread exiting")
                break
            if self.protocol in ("tcp", "both"):
                self.scan_tcp_port(port)
            if self.protocol in ("udp", "both"):
                self.scan_udp_port(port)
            self.queue.task_done()

    def scan(self):
        if self.debug:
            print(f"[DEBUG] Starting scan...")
        
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        threads = []
        worker_count = min(self.threads, max(1, self.end_port - self.start_port + 1))

        if self.debug:
            print(f"[DEBUG] Spawning {worker_count} worker threads")

        for i in range(worker_count):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            threads.append(thread)
            if self.debug:
                print(f"[DEBUG] Thread {i} started")

        if self.debug:
            print(f"[DEBUG] Waiting for queue to be processed...")
        
        self.queue.join()
        
        if self.debug:
            print(f"[DEBUG] Queue processed, sending kill signals...")
        
        for _ in range(len(threads)):
            self.queue.put(None)
        
        for i, thread in enumerate(threads):
            thread.join()
            if self.debug:
                print(f"[DEBUG] Thread {i} joined")

        if self.debug:
            print(f"[DEBUG] Scan complete. Found {len(self.results)} open port(s)")

        return sorted(self.results, key=lambda item: (item["protocol"], item["port"]))
