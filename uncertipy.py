import _thread
import argparse
import logging
import select
import socket
import ssl

import uncertipy.util, uncertipy.connection

def handle_connections(downstream_socket, method, cert_file, key_file):
    insecure_data = b""
    count = 0
    try:
        uncertipy_connection = uncertipy.connection.UncertipyConnection(downstream_socket, logger)
        connection = uncertipy.connection.Connection(uncertipy_connection.downstream_socket, logger)
        logger.debug(f'Got connection from {connection.to_str()}')

        interception = uncertipy.connection.generate_interception(connection, method, cert_file, key_file, logger)
        logger.debug(f'Intercepted connection to {interception.hostname}')

        try:
            if not connection.upstream_port in uncertipy.util.CLEARTEXT_PORTS:
                uncertipy_connection.wrap_downstream(interception.context)

        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError) as e:
            logger.error(f"{connection.client_ip}: {connection.upstream_str} {e}")
            return

        uncertipy_connection.set_upstream(connection.upstream_ip, connection.upstream_port)
        if uncertipy_connection.upstream_socket and not connection.upstream_port in uncertipy.util.CLEARTEXT_PORTS:
            try:
                uncertipy_connection.wrap_upstream(connection.upstream_sni)
            except (ssl.SSLZeroReturnError, TimeoutError):
                logger.debug("Cannot wrap upstream socket. Destroying also the TCP socket.")
                uncertipy_connection.upstream_socket = None

        if not uncertipy_connection.upstream_socket:
            logger.info(f"Cannot connect to {connection.upstream_ip}: with TLS.")

        try:
            while count < 5:
                count += 1
                if uncertipy_connection.upstream_socket:
                    ready = select.select([uncertipy_connection.downstream_socket, uncertipy_connection.upstream_socket], [], [], 1)

                else:
                    logger.info(f'Could not connect to upstream {connection.upstream_sni}, connecting only to downstream {connection.client_ip}')
                    ready = select.select([uncertipy_connection.downstream_socket], [], [], 1)

                for ready_socket in ready[0]:
                    logger.debug(f'Socket: {ready_socket}')
                    if ready_socket == uncertipy_connection.downstream_socket:
                        try:
                            from_client = uncertipy_connection.downstream_socket.recv(4096)

                        except TimeoutError:
                            logger.exception(f'{connection.client_ip}: {connection.upstream_sni} timed out')
                            count = 5
                            break

                        logger.debug(f'Client: {from_client}')
                        if from_client == b'':
                            count = 5
                            break

                        if uncertipy_connection.upstream_socket:
                            uncertipy_connection.upstream_socket.send(from_client)
                            logger.debug(f'Sending to server: {from_client}')

                        count = 0

                    elif ready_socket == uncertipy_connection.upstream_socket:
                        try:
                            from_server = uncertipy_connection.upstream_socket.recv(4096)

                        except TimeoutError:
                            count = 1
                            from_server = b''

                        logger.debug(f'Server: {from_server}')
                        if from_server:
                            insecure_data += from_server

                        if from_server != b'':
                            count = 0

                        uncertipy_connection.downstream_socket.send(from_server)
                        logger.debug(f'Sending to client: {from_server}')

                    else:
                        continue

                    break

        except (ConnectionResetError, ssl.SSLEOFError, TimeoutError):
            if not insecure_data:
                logger.exception(f"{connection.client_ip}: {connection.upstream_str} Nothing received, someone closed connection")

        except Exception as e:
            logger.exeception(e)

        finally:
            if insecure_data:
                logger.critical(f'{connection.client_ip}: {connection.upstream_str} intercepted data')

            else:
                logger.info(f'{connection.client_ip}: {connection.upstream_str} Nothing received')

            uncertipy_connection.close()

    except Exception as e:
        logger.exception(f'Exception encountered: {e}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help='Address to listen on.', default='127.0.0.1')
    parser.add_argument('-p', '--port', type=int, help='Port to listen on.', required=True)
    parser.add_argument('-c', '--cert', help='Path to a valid TLS certificate, signed by a CA.', required=True)
    parser.add_argument('-k', '--key', help='Path to the certificate key.', required=True)
    parser.add_argument('-m', '--method', help='TLS interception method to use.', required=True, choices=uncertipy.util.INTERCEPTION_METHODS)
    #parser.add_argument('-u', '--upstream-proxy', help='Upstream proxy to intercept requests with. Ex: 127.0.0.1:8080', required=False)
    parser.add_argument('-v', '--verbose', help='Verbose output.', action='store_true')
    parser.add_argument('-d', '--debug', help='Debug output.', action='store_true')

    args = parser.parse_args()

    address = args.address
    port = args.port
    cert_file = args.cert
    key_file = args.key
    method = args.method
    #upstream_proxy = args.upstream_proxy

    logger = uncertipy.util.logger("Log")

    if args.debug:
        logger.setLevel(logging.DEBUG)

    elif args.verbose:
        logger.setLevel(logging.INFO)

    else:
        logger.setLevel(logging.WARNING)

    logger.info(f'Listening on {address}:{port}')
    logger.info(f'Intercepting TLS connections using {method} method.')
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(5)

    while True:
        try:
            client, addr = listener.accept()
            client.settimeout(30)
            logger.debug(f'Request received from {addr}')
            _thread.start_new_thread(handle_connections, (client, method, cert_file, key_file))

        except Exception as e:
            logger.exception(f'Error while handling request: {e}')