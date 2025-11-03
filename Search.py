import subprocess
import shutil
import argparse
import sys
import re
import os
import ftplib
import requests
import json
import tempfile
import socket
import ssl
import socket
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def GetUserInput():
    default_output = os.path.join(os.getcwd(), "results")
    parser = argparse.ArgumentParser(
        description="Search.py - Works with Host and optional parameters"
    )

    parser.add_argument("host", type=str, help="Host to search")

    parser.add_argument("-t", "--test", type=str, help="Test message", default=None)

    parser.add_argument("-y", action="store_true", help="Enable aggressive mode")
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        default=default_output,
        help=f"Output directory (default: {default_output})",
    )
    parser.add_argument(
        "-T",
        "--speed",
        type=int,
        choices=range(0, 6),
        default=2,
        metavar="LEVEL",
        help="Speed level: 0‑5 (default: %(default)s)",
    )
    args = parser.parse_args()

    return {
        "host": args.host,
        "testMessage": args.test,
        "agressiveMode": args.y,
        "outputDir": args.output,
        "speed": args.speed,
    }


def checkAndInstall():
    inputs = GetUserInput()
    path = inputs["outputDir"]
    print(path)
    if not os.path.exists(path):
        print("[+] Create results dir")
        os.makedirs(path)

    packages = ["nmap", "dirsearch"]
    download_packages = ["sudo", "apt", "install", "-y"]
    for pack in packages:
        if not shutil.which(pack):
            download_packages.append(pack)
            print(f"Download {pack}")

    if len(download_packages) > 4:
        update_args = ["sudo", "apt", "update"]
        print("Update apt")
        subprocess.run(update_args)
        print("Packs are download")
        subprocess.run(download_packages)
        print("Please restart tool")
        sys.exit(0)


class PortScan:
    def __init__(self, host, agressiveMode=False, outputDir="./results", speed="2"):
        self.log = "\n\n***************HOST SCAN***************\n\n"
        self.host = host
        self.agressiveMode = agressiveMode
        self.ports = ""
        self.port_services = ""
        self.outputDir = outputDir
        self.speed = speed

    def portScan(self):

        self.log += "==========PORTSCAN==========\n"
        print("==========PORTSCAN==========\n")
        path = os.path.join(self.outputDir, "nmapScan.txt")
        if not self.host:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += "Please enter Host"
            print("Please enter Host")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            f"-T{self.speed}",
            "-oN",
            path,
            "-vv",
        ]
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        port_pattern = r"(\d+)/(udp|tcp)"
        ports_with_protocol = re.findall(port_pattern, scan.stdout)

        if not ports_with_protocol:
            self.log += "No open Port\n"
            print("No open Port")
            return ""

        ports_num = list(set(port[0] for port in ports_with_protocol))
        ports = ",".join(ports_num)
        self.log += f"[+] Finded ports: {ports}\n\n"
        print(f"[+] Finded ports: {ports}\n\n")
        self.ports = ports

    def agressiveScan(self):
        self.log += "==========AGRESIVE SCAN==========\n"
        print("==========AGRESIVE SCAN==========\n")

        path = os.path.join(self.outputDir, "agresiveScan.txt")
        continue_agresive_scan = "y"
        if self.agressiveMode == False:
            continue_agresive_scan = input("Do you Want a Agresive scan? [y/N] ")
            self.log += f"Do you Want a Agresive scan? [y/N] {continue_agresive_scan}\n"

        if continue_agresive_scan.lower() != "y":
            self.log += "Pass the agresive Scan\n"
            print("Pass the agresive Scan\n")
            return

        if not self.host or not self.ports:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Ports or Host\n"
            print("Please enter Ports or Host\n")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            f"-T{self.speed}",
            "-A",
            "-oN",
            path,
            "-vv",
            "-p",
            self.ports,
        ]
        self.log += "[+] Please wait this took a lot time\n"
        print("[+] Please wait this took a lot time")
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION--\n-")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        self.log += f"[+] If You want see result go {path}\n"
        print(f"[+] If You want see result go {path}\n")

    def checkServices(self):

        self.log += "==========SERVICES==========\n"
        print("==========SERVICES==========\n")

        path = os.path.join(self.outputDir, "serviceScan.txt")
        if not self.host or not self.ports:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---")
            self.log += "Please enter Ports or Host"
            print("Please enter Ports or Host")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            f"-T{self.speed}",
            "-oN",
            path,
            "-vv",
            "-p",
            self.ports,
        ]
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        try:
            services = scan.stdout.split("\n\n")[1]
            self.log += services + "\n\n"
            print(services + "\n\n")
        except:
            services = scan.stdout
            self.log += services + "\n\n"
            print(services + "\n\n")

        pattern = re.compile(r"^(\d+)/(?:tcp|udp)\s+\w+\s+(\S+)", re.MULTILINE)

        matches = pattern.findall(scan.stdout)

        port_services = {service: port for port, service in matches}
        self.port_services = port_services


class Ftp:
    def __init__(
        self,
        host,
        port=21,
        local_dir="results/ftp",
        timeout=10,
    ):
        self.log = "\n\n***************FTP SCAN***************\n\n"
        self.port = int(port)
        self.host = host
        self.timeout = timeout
        self.local_dir = os.path.join(local_dir, "ftp")
        self.user = "anonymous"
        self.passwd = "anonymous"
        self.anonymousLogin = False

    def checkAnonymousFtp(self):
        try:
            self.log += "==========ANONYMOUS LOGIN==========\n"
            print("==========ANONYMOUS LOGIN==========\n")
            ftp = ftplib.FTP()
            ftp.set_pasv(True)
            ftp.connect(host=self.host, port=self.port, timeout=self.timeout)

            ftp.login(user=self.user, passwd=self.passwd)
            self.log += f"[+] Anonymous FTP login successful on {self.host}!\n"
            print(f"[+] Anonymous FTP login successful on {self.host}!\n")
            ftp.quit()
            self.anonymousLogin = True
            return True
        except ftplib.all_errors as e:
            print(f"[-] Anonymous FTP login not open {self.host}: {e}")
            return False

    def downloadDir(self, ftp, remote_dir):
        try:
            items = []
            ftp.dir(lambda x: items.append(x))

            for item in items:
                parts = item.split()
                name = parts[-1]
                is_dir = item.startswith("d")

                if name in (".", ".."):
                    continue

                remote_path = (
                    f"{remote_dir}/{name}" if remote_dir != "/" else f"/{name}"
                )
                local_path = os.path.join(self.local_dir, name)

                if is_dir:
                    if not os.path.exists(local_path):
                        os.makedirs(local_path)
                    print(f"[+] Created local directory: {local_path}")

                    try:
                        ftp.cwd(remote_path)
                        self.downloadDir(ftp, remote_path)
                        ftp.cwd("..")
                    except ftplib.error_perm as e:
                        print(f"[-] Cannot access directory {remote_path}: {e}\n")
                        self.log += f"[-] Cannot access directory {remote_path}: {e}\n"
                else:
                    try:
                        with open(local_path, "wb") as local_file:
                            print(
                                f"[+] Downloading file: {remote_path} to {local_path}\n"
                            )
                            self.log += (
                                f"[+] Downloading file: {remote_path} to {local_path}\n"
                            )
                            ftp.retrbinary(f"RETR {name}", local_file.write)
                    except ftplib.error_perm as e:
                        print(f"[-] Failed to download {remote_path}: {e}\n")
                        self.log += f"[-] Failed to download {remote_path}: {e}\n"

        except ftplib.all_errors as e:
            print(f"[-] Error in directory {remote_dir}: {e}\n")
            self.log += f"[-] Error in directory {remote_dir}: {e}\n"

    def getFiles(self):
        try:
            if self.anonymousLogin == False:
                print("[-] Anonymous login false, Can't download files")
                self.log += "[-] Anonymous login false, Can't download files"
                return

            ftp = ftplib.FTP()
            ftp.set_pasv(True)
            ftp.connect(host=self.host, port=self.port, timeout=self.timeout)
            ftp.login(user=self.user, passwd=self.passwd)

            if not os.path.exists(self.local_dir):
                os.makedirs(self.local_dir)

            self.downloadDir(ftp, "/")

            ftp.quit()
            print("[+] Download completed!\n")
            self.log += "[+] Download completed!\n"
            return True

        except ftplib.all_errors as e:
            print(f"[-] Error: {e}")
            return False


class Http:
    def __init__(
        self, host, port=80, agressiveMode=False, domain=None, outputDir="./results"
    ):
        self.log = "\n***************HTTP SCAN***************\n"
        self.protocol = "http"
        self.host = host
        self.port = port
        self.domain = domain
        self.agressiveMode = agressiveMode
        self.outputDir = outputDir

    def robotsTxt(self):
        self.log += "\n==========ROBOTS.TXT==========\n"
        print("==========ROBOTS.TXT==========\n")

        if not self.host or not self.port:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Port or Host\n"
            print("Please enter Port or Host\n")
            return
        r = requests.get(
            f"{self.protocol}://{self.host}:{self.port}/robots.txt", timeout=5
        )
        if r.status_code == 200:
            self.log += f"{r.text}\n"
            print(f"{r.text}")
        else:
            print(f"[-] Robots.txt not found: {r.status_code}\n")
            self.log += f"[-] Robots.txt not found: {r.status_code}\n"

    def getHeader(self):
        self.log += "\n==========HEADERS==========\n"
        print("==========HEADERS==========\n")
        if not self.host or not self.port:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Port or Host\n"
            print("Please enter Port or Host\n")
            return
        r = requests.get(f"{self.protocol}://{self.host}:{self.port}", timeout=5)
        headers = dict(r.headers)
        self.log += f"[+] StatusCode: {r.status_code}\n"
        print(f"[+] StatusCode: {r.status_code}")
        self.log += "[+] Headers:\n"
        print("[+] Headers")
        self.log += json.dumps(headers, indent=4) + "\n"
        print(json.dumps(headers, indent=4))

    def mainPage(self):
        self.log += "\n==========MAINPAGE==========\n"
        print("==========MAINPAGE==========\n")
        path = os.path.join(self.outputDir, "mainPage.bin")
        if not self.host or not self.port:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Port or Host\n"
            print("Please enter Port or Host\n")
            return

        self.log += f"If You want see result go {path}\n"
        print(f"If You want see result go {path}\n")
        with requests.get(
            f"{self.protocol}://{self.host}:{self.port}", stream=True, timeout=10
        ) as r:
            r.raise_for_status()
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

    def dirsearch(self):
        self.log += "\n==========DIRSEARCH==========\n"
        print("==========DIRSEARCH==========\n")
        path = os.path.join(self.outputDir, "dirsearch.txt")
        continue_scan = "y"
        if self.agressiveMode == False:
            continue_scan = input("Do you Want a Dirsearch? [y/N] ")
            self.log += f"Do you Want a Dirsearch? [y/N] {continue_scan}\n"

        if continue_scan.lower() != "y":
            self.log += "Pass the Dirsearch\n"
            print("Pass the Dirsearch\n")
            return

        if not self.host or not self.port:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Port or Host\n"
            print("Please enter Port or Host\n")
            return

        args = [
            "sudo",
            "dirsearch",
            "-u",
            f"{self.protocol}://{self.host}:{self.port}",
            "-o",
            path,
        ]
        tmpdir = tempfile.mkdtemp()
        cwd = os.getcwd()

        self.log += "[+] Please wait this took a lot time\n"
        print("[+] Please wait this took a lot time")

        try:
            os.chdir(tmpdir)
            scan = subprocess.run(args, capture_output=True, check=True, text=True)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)
        self.log += f"[+] If You want see result go {path}\n"
        print(f"[+] If You want see result go {path}\n")

        if scan.stderr:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")


class Https(Http):
    def __init__(
        self, host, port=443, agressiveMode=False, domain=None, outputDir="./results"
    ):
        super().__init__(
            host,
            port=int(port),
            agressiveMode=agressiveMode,
            domain=domain,
            outputDir=outputDir,
        )
        self.protocol = "https"
        self.log = "\n***************HTTPS SCAN***************\n"

    def pretty_print(self, obj):
        log_entry = json.dumps(obj, indent=2, ensure_ascii=False)

        print(log_entry)
        self.log += log_entry + "\n"

    @staticmethod
    def cert_to_dict(cert: x509.Certificate) -> dict:
        def rfc4514(name):
            try:
                return name.rfc4514_string()
            except Exception:
                return str(name)

        subject = rfc4514(cert.subject)
        issuer = rfc4514(cert.issuer)

        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        san_list = []
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            san_list = san.get_values_for_type(x509.DNSName)
        except Exception:
            san_list = []

        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

        pub = cert.public_key()
        try:
            pub_bytes = pub.public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo,
            )
            pub_type = pub.__class__.__name__
        except Exception:
            pub_bytes = None
            pub_type = pub.__class__.__name__

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": hex(cert.serial_number),
            "version": (
                cert.version.name
                if hasattr(cert.version, "name")
                else str(cert.version)
            ),
            "not_before": not_before.astimezone(timezone.utc).isoformat(),
            "not_after": not_after.astimezone(timezone.utc).isoformat(),
            "signature_algorithm": (
                cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm
                else None
            ),
            "san": san_list,
            "fingerprint_sha256": fingerprint_sha256,
            "public_key_type": pub_type,
        }

    def verify_tls(self, timeout: float = 5.0) -> dict:
        self.log += "\n==========VERIFY TLS==========\n"
        print("==========VERIFY TLS==========\n")
        hostname_for_sni = self.domain if self.domain else self.host

        # Strict context for verification
        verify_ctx = ssl.create_default_context()
        verify_ctx.check_hostname = True
        verify_ctx.verify_mode = ssl.CERT_REQUIRED

        der_cert = None
        cipher_info = None  # Renamed to avoid confusion with the exception block
        verified = True
        verification_error = None

        try:
            # Attempt 1: Strict Verification
            with socket.create_connection(
                (self.host, self.port), timeout=timeout
            ) as sock:
                with verify_ctx.wrap_socket(
                    sock, server_hostname=hostname_for_sni
                ) as ssock:
                    cipher_info = ssock.cipher()
                    der_cert = ssock.getpeercert(binary_form=True)

        except ssl.SSLCertVerificationError as e:
            verified = False
            verification_error = e.reason

            # Context 2: No Verification, for data retrieval only
            no_verify_ctx = ssl.create_default_context()
            no_verify_ctx.check_hostname = False
            no_verify_ctx.verify_mode = ssl.CERT_NONE

            try:
                # Attempt 2: Retrieve cert data without verification
                with socket.create_connection(
                    (self.host, self.port), timeout=timeout
                ) as sock:
                    with no_verify_ctx.wrap_socket(
                        sock, server_hostname=hostname_for_sni
                    ) as ssock:
                        # Success here means we get the cipher and cert
                        cipher_info = ssock.cipher()
                        der_cert = ssock.getpeercert(binary_form=True)
            except Exception as inner_e:
                # Fatal failure even without verification
                return {
                    "host": self.host,
                    "port": self.port,
                    "verified_hostname": hostname_for_sni,
                    "verified": False,
                    "error": f"Connection failed after verification error: {inner_e}",
                }

        except Exception as e:
            # Catch general connection/socket errors
            return {
                "host": self.host,
                "port": self.port,
                "verified_hostname": hostname_for_sni,
                "verified": False,
                "error": str(e),
            }

        if not der_cert:
            return {
                "host": self.host,
                "port": self.port,
                "verified_hostname": hostname_for_sni,
                "verified": False,
                "error": "Could not retrieve server certificate.",
            }

        # If we reach here, der_cert and cipher_info have been successfully retrieved
        cert = x509.load_der_x509_certificate(der_cert)

        result = {
            "host": self.host,
            "port": self.port,
            "verified_hostname": hostname_for_sni,
            "verified": verified,
            "cipher": {
                # Use cipher_info instead of cipher and assume it's a tuple or None
                "name": cipher_info[0] if cipher_info else None,
                "protocol": cipher_info[1] if cipher_info else None,
                "bits": cipher_info[2] if cipher_info else None,
            },
            "certificate": self.cert_to_dict(cert),
        }

        if verification_error:
            result["verification_error"] = verification_error

        return result


class Services:
    def __init__(self):
        self.service_map = {}
        self.inputs = GetUserInput()

    def portScan(self):
        print("***************HOST SCAN***************\n")
        scan = PortScan(
            self.inputs["host"],
            self.inputs["agressiveMode"],
            outputDir=self.inputs["outputDir"],
            speed=self.inputs["speed"],
        )
        scan.portScan()
        scan.checkServices()
        scan.agressiveScan()
        self.service_map = scan.port_services
        return (scan.log, scan.port_services)

    def ftpScan(self, port):
        print("***************FTP SCAN***************\n")
        ftp = Ftp(self.inputs["host"], port, local_dir=self.inputs["outputDir"])
        ftp.checkAnonymousFtp()
        ftp.getFiles()
        return ftp.log

    def httpScan(self, port):
        print("***************HTTP SCAN***************\n")
        http = Http(
            self.inputs["host"],
            port,
            agressiveMode=self.inputs["agressiveMode"],
            outputDir=self.inputs["outputDir"],
        )
        http.robotsTxt()
        http.getHeader()
        http.mainPage()
        http.dirsearch()
        return http.log

    def httpsScan(self, port):
        print("***************HTTPS SCAN***************\n")
        https = Https(
            self.inputs["host"],
            port=int(port),
            agressiveMode=self.inputs["agressiveMode"],
            outputDir=self.inputs["outputDir"],
        )
        scan_result = https.verify_tls()
        https.pretty_print(scan_result)
        return https.log

    def services(self):
        services_log = ""
        try:
            if "ftp" in self.service_map:
                services_log += self.ftpScan(self.service_map["ftp"])
            if "http" in self.service_map:
                services_log += self.httpScan(self.service_map["http"])
            if "https" in self.service_map:
                services_log += self.httpsScan(self.service_map["https"])

        except KeyError as e:
            print(f"[-] Error: Service {e} not found in self.services")
            services_log += f"[-] Error: Service {e} not found in self.services\n"
        except Exception as e:
            print(f"[-] Error in services method: {e}")
            services_log += f"[-] Error in services method: {e}\n"
        return services_log


def main():
    log = ""
    checkAndInstall()
    services_scan = Services()
    port_scan = services_scan.portScan()
    log += port_scan[0]
    services_log = services_scan.services()
    log += services_log
    inputs = GetUserInput()
    outputDir = inputs["outputDir"]
    path = os.path.join(outputDir, "mainLogs.log")
    with open(path, "w") as file:
        file.write(log)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nEXIT...\n\n")
        sys.exit(1)
