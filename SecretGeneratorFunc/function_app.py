import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import logging
logging.basicConfig(level=logging.DEBUG)
import secrets
import string
import json

app = func.FunctionApp()

@app.function_name(name="HttpTrigger1")
@app.route(route="secrets")
def test_function(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f'SecretFunction: Received a request')

    (valid, name, vault, length) = validate_request(req)

    if not valid:
        logging.error(f'SecretFunction: INVALID REQUEST')
        return json_response({"message": "You must supply a request body containing vault, name and length"}, 400)
    
    return save_secret(f"https://{vault}.vault.azure.net", name, generate_secret(length))


def save_secret(key_vault_uri, name, secret_value):
    try:
        client = SecretClient(vault_url=key_vault_uri, credential=DefaultAzureCredential())
        client.set_secret(name, secret_value)
        logging.info(f"Saved Secret {name} to {key_vault_uri}/{name}")
        return json_response({"message": "Successfully added secret", "secretUri": f"{key_vault_uri}/{name}"}, 200)
    except (RuntimeError, Exception) as e:
        logging.error(f"Failed to save secret {e}")
        return json_response({"message": f"Failed to save secret {key_vault_uri}/{name}"}, 500)
 

def json_response(response_object, status):
    return func.HttpResponse(
             json.dumps(response_object),
             mimetype="application/json",
             status_code=status
        )


def validate_request(req):
    req_body = req.get_json()
    if not req_body:
         return (False, None, None, None)
    
    try:
        valid = True
        vault = req_body.get('vault')
        if vault and len(vault) > 6:
            logging.info(f'SecretFunction: vault = {vault}')
        else:
            valid = False

        name = req_body.get('name')
        if name and len(name) > 6:
            logging.info(f'SecretFunction: name = {name}')
        else:
            valid = False

        length = req_body.get('length')
        if length:
            logging.info(f'SecretFunction: length = {length}')
        else:
            valid = False
        
        return (valid, name, vault, length)
    except ValueError as e:
        logging.error(f'SecretFunction: failed to parse = {req_body}, {e}')
        return (False, None, None, None)


def generate_secret(size):
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(size))
    return password