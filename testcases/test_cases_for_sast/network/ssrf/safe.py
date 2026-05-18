import requests
url = request.args.get('url')
if url.startswith(('http://example.com','https://example.com')):
    response = requests.get(url)
