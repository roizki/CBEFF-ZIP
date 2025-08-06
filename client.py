import requests

url = "http://localhost:5000/old-biometric-endpoint"
response = requests.get(url, allow_redirects=True)

print("== HTTP Result ==")
print("Status Code:", response.status_code)
print("Final URL:", response.url)
print("Response Body:\n")
print(response.text)
