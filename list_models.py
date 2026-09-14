import os
from mistralai.client import Mistral

client = Mistral(api_key=os.environ['MISTRAL_API_KEY'])
models = client.models.list()

for m in models.data:
    print(m.id)
