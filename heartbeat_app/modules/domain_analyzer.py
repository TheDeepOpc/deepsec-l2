import requests
from bs4 import BeautifulSoup
import re

def clean_text(text):
    """Matndagi ortiqcha bo'shliqlar va belgilarni tozalash"""
    if text:
        return re.sub(r'\s+', ' ', text).strip().replace('\xa0', '')
    return "aniqlanmadi"

def get_whois_data(domain: str):
    """cctld.uz saytidan domen haqida WHOIS ma'lumotlarini oladi."""
    url = f"https://cctld.uz/whois/?domain={domain}&zone=uz"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        table = soup.find('table', class_='table table-striped')
        
        if not table:
            return {"error": "Ma'lumot topilmadi yoki domen ro'yxatdan o'tmagan"}

        tbody = table.find('tbody')
        if not tbody:
            return {"error": "Jadvalning asosiy qismi topilmadi."}
            
        rows = tbody.find_all('tr')

        data = {}

        for row in rows:
            tds = row.find_all('td')
            for i in range(0, len(tds), 2):
                if i + 1 < len(tds):
                    key = clean_text(tds[i].get_text()).replace(':', '')
                    value = clean_text(tds[i+1].get_text())
                    
                    if key:
                        # Kalitlarni standartlashtirish
                        if "Registrator" in key:
                            data["registrar"] = value
                        elif "Yaratilgan sana" in key:
                            data["creation_date"] = value
                        elif "Yaroqlilik muddati" in key:
                            data["expiration_date"] = value
                        elif "NS server haqida ma`lumot" in key:
                            # NS serverlarni to'plab, listga joylash
                            if "ns_servers" not in data:
                                data["ns_servers"] = []
                            data["ns_servers"].append(value)
                        else:
                            data[key.lower()] = value
        
        # Agar NS serverlar topilmasa
        if "ns_servers" not in data:
            data["ns_servers"] = ["aniqlanmadi"]

        return data

    except requests.exceptions.RequestException as e:
        return {"error": f"Tarmoq xatosi: {e}"}
    except Exception as e:
        return {"error": f"Noma'lum xatolik: {e}"}

if __name__ == '__main__':
    # Test uchun
    domain_name = "uzinfocom.uz"
    whois_info = get_whois_data(domain_name)
    
    if "error" in whois_info:
        print(f"Xatolik: {whois_info['error']}")
    else:
        print(f"'{domain_name}' domeni uchun ma'lumotlar:")
        for key, value in whois_info.items():
            if isinstance(value, list):
                print(f"  {key.replace('_', ' ').title()}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  {key.replace('_', ' ').title()}: {value}")

