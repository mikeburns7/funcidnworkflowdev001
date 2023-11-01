import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import logging
import requests
import json


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="delatlassianacct", methods=["POST"])
def delatlassianacct(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('delatlassianacct HTTP trigger function processed a request.')
    trigger = "delatlassianacct"
    atlassian_account_id = req.params.get('atlassian_account_id')

    if not atlassian_account_id:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            atlassian_account_id = req_body.get('atlassian_account_id')
            userprincipalname = req_body.get('userprincipalname')
            token = get_token()
            result = http_request(token, atlassian_account_id,userprincipalname) 
        
        if result.status_code == 200:
            return func.HttpResponse(f"SUCCESS: {userprincipalname} Atlassian Cloud SaaS account deleted - {atlassian_account_id} status_code: {result.status_code} message: {result.text}" )
        else:
            return func.HttpResponse(
                f"ERROR: {userprincipalname} Atlassian Cloud SaaS account NOT deleted - {atlassian_account_id}: Error Code: {result.status_code} Error Message: {result.text}",
                status_code=result.status_code
        )

def get_token(trigger):
    
    keyVaultName = "kv-identitynow"
    KVUri = f"https://{keyVaultName}.vault.azure.net"

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=KVUri, credential=credential)
    except Exception as error:
        logging.info("ERROR {}".format(error))
    if trigger=="delatlassianacct":
        api_token = (client.get_secret("atlassian-apikey")).value
    elif trigger=="delgcpacct":
        api_token = (client.get_secret("gcp-apikey")).value
    return api_token

def http_request(api_token, atlassian_account_id,userprincipalname):
    # delete atlassian account https://developer.atlassian.com/cloud/admin/user-provisioning/rest/api-group-atlassian-account-for-admins/#api-users-account-id-manage-delete
    base_url = "https://api.atlassian.com"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    url = f"{base_url}/users/{atlassian_account_id}/manage/lifecycle/delete"
    response = requests.post(url, headers=headers)
    return response
    

@app.route(route="delgcpacct", auth_level=func.AuthLevel.ANONYMOUS)
def delgcpacct(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('delgcpacct HTTP trigger function processed a request.')
    trigger = "delgcpacct"
    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

            json_entry = json.dumps({
                "name": "Bard",
                "age": 1,
                "occupation": "Language Model"
            })

            with open("/tmp/data.json", "w") as f:
                json.dump(json_entry, f)
            
            f = open("/tmp/data.json", "r")
            contents = f.read()
    if name:
        return func.HttpResponse(f"{contents}. ")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )