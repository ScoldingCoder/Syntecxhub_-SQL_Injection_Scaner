import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] ="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

# function to get all forms
def get_forms (url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

#function to get form details
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type =input_tag.attrs.get("type","text")
        input_name =input_tag.attrs.get("name")
        input_value =input_tag.attrs.get("value","")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    errors ={ "quoted string is not properly terminated",
             "unclosed quotation mark after the character string",
             "you have an error in your SQL syntax"
               }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def sql_injection_scan(url):
    forms = get_forms(url)
    print (f"[+] Detected {len(forms)} form(s) on {url}. ")

    for form in forms:
        details = form_details(form)
  
        target_url = urljoin(url, details["action"]) if details["action"] else url

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["name"] is None:
                    continue
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            print(f"    testing payload {i!r} -> {target_url}")

            if details["method"] == "post":
                res = s.post(target_url, data=data)
            else:
                res = s.get(target_url, params=data)

            if vulnerable(res):
                print("[!] SQL injection vulnerability detected in form targeting", target_url)
                break
        else:
            print("[-] No SQL injection vulnerability detected in form targeting", target_url)

if __name__ =="__main__":

    urlToBeChecked = ""
    sql_injection_scan(urlToBeChecked)