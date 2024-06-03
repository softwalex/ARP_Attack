import socket

def get_website_from_ip(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return None

# Example usage:
ip_address = "216.239.32.116"
website = get_website_from_ip(ip_address)
if website:
    print(f"The website associated with the IP {ip_address} is: {website}")
else:
    print(f"No website found for the IP {ip_address}")
