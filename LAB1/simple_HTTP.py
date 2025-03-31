from pwn import *

# Define the target URL
url = "http://ipinfo.io/ip"

# Create a request using pwntools' remote() function
with remote("ipinfo.io", 80) as conn:
    # Send an HTTP GET request
    conn.send(b"GET /ip HTTP/1.1\r\n")
    conn.send(b"Host: ipinfo.io\r\n")
    conn.send(b"Connection: close\r\n\r\n")
    
    # Receive the response
    response = conn.recvall().decode()

# Extract the IP address (response body is usually the last part of the response)
ip = response.split("\r\n")[-1]
print(ip)
