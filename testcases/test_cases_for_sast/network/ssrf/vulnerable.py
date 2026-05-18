import requests
url = request.args.get('url')
response = requests.get(url)  # DANGEROUS
