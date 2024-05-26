import requests
import re

internal_blacklist = ["https://scam.com"]


def check_with_virus_total(url, virus_total_token):
    virus_total_base_endpoint = "https://www.virustotal.com/api/v3/"

    payload = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_token,
        "content-type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.post(virus_total_base_endpoint + "urls", data=payload, headers=headers).json()
        report_id = response.get("data", {}).get("id")
        headers = {
            "accept": "application/json",
            "x-apikey": virus_total_token
        }
        response = requests.get(virus_total_base_endpoint + f"analyses/{report_id}", headers=headers).json()
        return response.get("data", {}).get("attributes", {}).get("stats")
    except Exception as e:
        print(f"An error occurred when checking url={url}", e)


def get_url_variations(url):
    if not re.match(r'^(http://|https://)', url):
        return ['http://' + url, 'https://' + url]
    return [url]


def identify_suspicious_links(message, virus_total_token):
    # 1 = automated report created, no action needed from moderators
    # 0 = no report required
    # -1 = automated report created, action needed from moderators

    url_pattern = re.compile(
        r'\b((http|https)://)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+)(/[a-zA-Z0-9@:%_\+.~#?&//=,-]*)?\b')
    urls = url_pattern.findall(message)
    actions_per_url = {}
    if len(urls) > 0:
        for url in urls:
            suspicious = 0
            num_vendors = 0
            for u in get_url_variations(url):
                if u in internal_blacklist:
                    actions_per_url[url] = 1
                    break
                else:
                    stats = check_with_virus_total(u, virus_total_token)
                    total = sum(stats.values())
                    if total != 0:
                        if stats.get("malicious") >= 5:
                            internal_blacklist.append(u)
                            actions_per_url[url] = 1
                            break
                        elif stats.get("suspicious")/total > 0.5:
                            actions_per_url[url] = -1
                            break
                        else:
                            # check other variations before making decision
                            suspicious += stats.get("suspicious")
                            num_vendors += total
            if num_vendors == 0:
                actions_per_url[url] = -1
            elif suspicious/num_vendors > 0.5:
                actions_per_url[url] = -1
            else:
                actions_per_url[url] = 0
    return actions_per_url


