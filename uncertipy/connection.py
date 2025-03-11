import socket
import threading
import time

import OpenSSL

import uncertipy.util


def counter():
    i = 0
    while True:
        yield i
        i += 1

connection_counter = counter()

class UncertipyConnection(object):

    def __init__(self, downstream_socket, logger):
        self.logger = logger
        self.downstream_socket = downstream_socket
        self.downstream_socket.settimeout(10)
        self.upstream_socket = None
        self.upstream_context = None
        self.downstream_tls_buf = b""

    def set_upstream(self, ip, port):
        self.logger.debug(f"Connecting to TCP upstream {ip}:{port}")
        self.upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream_socket.settimeout(10)
        try:
            self.upstream_socket.connect((ip, port))
            self.logger.debug(f"Connected to TCP upstream {ip}:{port}")
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            self.logger.debug(f"Upstream connection failed with {e}")
            self.upstream_socket = None

    def wrap_downstream(self, context):
        self.logger.debug(f"Wrapping downstream with TLS")
        self.downstream_socket = context.wrap_socket(self.downstream_socket, server_side=True)
        self.downstream_socket.settimeout(10)
        self.logger.debug(f"Wrapped downstream with TLS")

    def wrap_upstream(self, hostname):
        self.logger.debug(f"Wrapping upstream with TLS")
        self.upstream_context = uncertipy.util.create_client_context()
        self.upstream_socket = self.upstream_context.wrap_socket(self.upstream_socket, server_hostname=hostname)
        self.upstream_socket.settimeout(10)
        self.logger.debug(f"Wrapped upstream with TLS")

    def close(self):
        try:
            self.downstream_socket.unwrap()
            self.upstream_socket.unwrap()

        except:
            pass

        self.downstream_socket.close()
        if self.upstream_socket:
            self.upstream_socket.close()


class Connection(object):

    def __init__(self, client_socket, logger):
        self.id = next(connection_counter)
        self.timestamp = time.time()
        self.lock = threading.Lock()
        self.logger = logger
        self.client_socket = client_socket
        self.client_name = str(client_socket.getpeername())
        self.client_ip = self.client_name.split("'")[1]
        self.client_port = int(self.client_name.split(" ")[1].split(')')[0]) #Dirty I know :)
        self.upstream_ip, self.upstream_port = uncertipy.util.sock_to_dest(self.client_socket)
        if self.upstream_ip == "127.0.0.1" and self.upstream_port == 9900:
            self.logger.debug(f"Setting debug upstream")
            self.upstream_port = 10000
        try:
            self.upstream_sni = uncertipy.util.SNIFromHello(self.client_socket.recv(4096, socket.MSG_PEEK))
        except (TimeoutError, ConnectionResetError):
            self.upstream_sni = None
        if self.upstream_sni:
            self.upstream_name = self.upstream_sni
        else:
            self.upstream_name = self.upstream_ip
        self.upstream_str = f"{self.upstream_ip}:{self.upstream_port}:{self.upstream_sni}"
        self.identifier = str([self.client_ip, self.upstream_name, self.upstream_port])

    def to_str(self):
        return f"ID: {self.id}, Client: {self.client_ip}:{self.client_port}, Upstream: {self.upstream_ip}:{self.upstream_port} '{self.upstream_sni}', Identifier: {self.identifier}"


class TLSInterception(object):

    def __init__(self, hostname, cert, key, original_cert_pem):
        self.hostname = hostname
        self.cert = cert
        self.key = key
        ctx = uncertipy.util.create_server_context()
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        self.context = ctx
        self.original_cert = original_cert_pem


def generate_interception(connection, method, cert_file, key_file, logger):
    cert_chain = uncertipy.util.get_server_cert_fullchain(connection.upstream_ip, connection.upstream_port, connection.upstream_sni)
    if not cert_chain:
        logger.info(f'No cert chain for {connection.upstream_sni}, generating one.')
        cert_chain = uncertipy.util.generate_certificate(cn=connection.upstream_sni)

    if connection.upstream_sni in uncertipy.util.GENERATED_CERTS:
        cert_file_path, key_file_path = uncertipy.util.GENERATED_CERTS[connection.upstream_sni]

    elif method == "self_signed":
        generated_cert, key = _generate_interception_self_signed(cert_chain)
        cert_file_path, key_file_path = uncertipy.util.save_cert_chain(generated_cert, key)

    elif method == "replaced_key":
        generated_cert, key = _generate_interception_replaced_key(cert_chain)
        cert_file_path, key_file_path = uncertipy.util.save_cert_chain(generated_cert, key)

    elif method == 'real_cert':
        cert_file_path = cert_file
        key_file_path = key_file

    elif method == "real_cert_CA":
        generated_cert, key = _generate_interception_real_cert_ca(cert_chain, cert_file, key_file)
        cert_file_path, key_file_path = uncertipy.util.save_cert_chain(generated_cert, key)

    else:
        raise Exception('Unknown interception method')

    uncertipy.util.GENERATED_CERTS[connection.upstream_sni] = [cert_file_path, key_file_path]
    return TLSInterception(connection.upstream_sni, cert_file_path, key_file_path, cert_chain)

def _generate_interception_self_signed(cert_chain):
    tmp_cert_chain = []
    for tmp_cert_pem in cert_chain:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        tmp_cert_chain.append(cert)

    tmp_cert_chain[0].set_issuer(tmp_cert_chain[0].get_subject())
    tmp_cert_chain[0], key = uncertipy.util.sign_certificate(tmp_cert_chain[0], issuer_cert=None)
    return [tmp_cert_chain[0]], key

def _generate_interception_replaced_key(cert_chain):
    generated_cert = []
    for tmp_cert_pem in cert_chain:
        partial_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        generated_cert.append(partial_cert)

    generated_cert[0], key = uncertipy.util.replace_public_key(generated_cert[0])
    return generated_cert, key

def _generate_interception_real_cert_ca(cert_chain, cert_file, key_file):
    real_cert_chain_pem = []
    with open(cert_file) as certf:
        certcontent = certf.read()

    buffer = ""
    for i in certcontent.split("\n"):
        if "CERTIFICATE" in i:
            if buffer:
                buffer = f"-----BEGIN CERTIFICATE-----\n{buffer}-----END CERTIFICATE-----\n"
                real_cert_chain_pem.append(buffer)
                buffer = ""
        else:
            buffer += f"{i}\n"

    real_cert_chain = []
    for real_cert_pem in real_cert_chain_pem:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, real_cert_pem.encode())
        real_cert_chain.append(cert)

    with open(key_file) as keyf:
        real_cert_chain_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keyf.read())

    orig_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_chain[0])

    tmp_cert_chain = [orig_cert]
    tmp_cert_chain.extend(real_cert_chain)

    cert, key = uncertipy.util.sign_certificate(tmp_cert_chain[0], key=None, issuer_cert=tmp_cert_chain[1],
                                               issuer_key=real_cert_chain_key)
    tmp_cert_chain[0] = cert

    return tmp_cert_chain, key
