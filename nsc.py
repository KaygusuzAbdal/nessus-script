import json
import requests

#Fonksiyon tekrarlarından kaçınmak ve okunabilirliği arttırmak amacıyla Class yapısı kullanıyoruz
class Nsc:
    #obje oluşturulduğunda bazı tanımlamaları otomatik yapmamızı sağlayan bir Constructor yapısı oluşturuyoruz
    def __init__(self):
        #config.json dosyasında yer alan credentials bilgilerini okuyoruz
        with open('config.json') as file:
            conf = json.load(file)
        #config dosyasında yer alan bilgilerle header oluşturuyoruz
        self.headers = {
            "X-ApiKeys": f"accessKey={conf['access-key']}; secretKey={conf['secret-key']}",
            "Content-Type": "application/json"
        }
        #session oluşturmak için kullanacağımız login datasını oluşturuyoruz
        self.login_data = {
            "username": f"{conf['username']}",
            "password": f"{conf['password']}"
        }
        #Nessusun çalıştığı adresi default olarak tanımlıyoruz
        self.NESSUS_URL = f"https://{conf['IP']}:8834"
        #session oluşturma fonksiyonunu çağırarak X-Cookie header'ı elde etmeye çalışıyoruz
        self.get_session()

    #X-Cookie değeri alabilmek için session oluşturma fonksiyonu
    def get_session(self):
        try:
            #https://IP:8834/session adresine istek atıp geri dönen cevabı response değişkeninde tutuyoruz
            response = requests.post(self.NESSUS_URL + "/session", json=self.login_data, verify=False)
            #response değişkenindeki token key'ini X-Cookie olarak class'ta tanımlı olan headers dictionary'e ekliyoruz
            self.headers["X-Cookie"] = response.json()["token"]
            return True
        except Exception:
            #eğer hatalı bir response alırsak programın kapanmadan çalışmasını sağlayabilmek ve hatanın nereden kaynaklı olduğunu bulabilmek için try-catch yapısı
            print("Session oluşturulamadı!")
            return False

    #tüm tarama sonuçlarını JSON formatında çekmemizi sağlayan fonksiyon
    def get_all_results(self, scan_id=None):
        if scan_id is None: #scan_id belirtilmediyse tüm taramaları alıyoruz
            scans = requests.get(self.NESSUS_URL + "/scans", headers=self.headers, verify=False)
            scans_json = {"scans" : []} #en son geri döndüreceğimiz boş bir dictionary tanımlıyoruz
            #tüm taramaların bilgilerini/detaylarını getiriyoruz
            for scan in scans.json()["scans"]:
                scan_item = requests.get(f"{self.NESSUS_URL}/scans/{scan['id']}", headers=self.headers, verify=False)
                scan_json = {"scan-id": str(scan["id"]), "details": scan_item.json(), "hosts": []}
                #taramaların yapıldığı sunuculara ait bilgileri getiriyoruz
                for host in scan_item.json()["hosts"]:
                    endpoint_item = requests.get(f"{self.NESSUS_URL}/scans/{scan['id']}/hosts/{host['host_id']}", headers=self.headers,
                                             verify=False)
                    #sunucu bilgileri endpoint json'da host-id, detais olarak tutulmaktadır {host-id:1, details:[blabla]}
                    endpoint_json = {"host-id": str(host["host_id"]), "details": endpoint_item.json()}
                    #tarama detaylarına sunucularla ilgili olan bilgileri dahil ediyoruz
                    scan_json["hosts"].append(endpoint_json)
                #taramaları en son "scans" dictionary key'i altında listeliyoruz
                scans_json["scans"].append(scan_json)
            return scans_json
        else:
            #eğer bir id verildiyse direkt o taramanın detaylarını alıyoruz
            scan = requests.get(f"{self.NESSUS_URL}/scans/{scan_id}", headers=self.headers, verify=False)
            scan_json = {"scan-id": str(scan_id), "details": scan.json(), "endpoints": []}
            #taramanın yapıldığı tüm sunucuları getiriyoruz
            for host in scan.json()["hosts"]:
                host_item = requests.get(f"{self.NESSUS_URL}/scans/{scan_id}/hosts/{host['host_id']}",
                                             headers=self.headers,
                                             verify=False)
                #sunucu bilgileri endpoint json'da host-id, detais olarak tutulmaktadır {host-id:1, details:[blabla]}
                endpoint_json = {"host-id": str(host["host_id"]), "details": host_item.json()}
                #tarama detaylarına sunucularla ilgili olan bilgileri dahil ediyoruz
                scan_json[str(scan_id)]["endpoints"].append(endpoint_json)
            return scan_json

    #sadece zafiyetleri listeleyebilmemizi sağlayan fonksiyon
    def get_vulnerabilities(self, scan_id=None):
        if scan_id is None: #scan_id belirtilmediyse tüm taramaları alıyoruz
            vulnerabilities = {"scans": []} #boş bir dictionary oluşturuyoruz
            for scan in self.get_all_results()["scans"]: #tüm sonuçlardaki scan key'inin değerini geziyoruz
                scan_json = {"scan-id": (scan["scan-id"]), "vulnerabilities": scan["details"]["vulnerabilities"]}
                vulnerabilities["scans"].append(scan_json) #scan-id ve vulnerabilities olmak üzere gerekli bilgileri ayrı bir dictionary'e alıyoruz
            return vulnerabilities
        else: #scan_id belirtildiyse
            vulnerabilities = {"scans": []} #boş bir dictionary oluşturuyoruz
            for scan in [x for x in self.get_all_results()["scans"] if x["scan-id"] == str(scan_id)]: #tüm sonuçlarda, scan-id'si parametre olarak gönderilen scan-id'ye eşit olan değerleri geziyoruz
                scan_json = {"scan-id": (scan["scan-id"]), "vulnerabilities": scan["details"]["vulnerabilities"]} #scan-id ve vulnerabilities olmak üzere gerekli bilgileri ayır bir dictionary'e alıyoruz
                vulnerabilities["scans"].append(scan_json) #önceden oluşturduğumuz dictionary'nin scan key'ine sonuçları ekliyoruz
            return vulnerabilities

    #zafiyetleri host,IP adress, Operation System gibi bilgilerle listeyebilmeyi sağlayan fonksiyon
    def get_vulns_with_info(self, scan_id=None):
        #eğer belirli bir tarama ID'si girilmediyse
        if scan_id is None:
            vulnerabilities = {"scans": []} #boş bir dictionary oluşturuyoruz
            for scan in self.get_all_results()["scans"]: #tüm sonuçlardaki scan key'inin değerini geziyoruz
                scan_json = {"scan-id": (scan["scan-id"]), "vulnerabilities": scan["details"]["vulnerabilities"],
                             "info": scan["details"]["info"]} #scan-id, vulnerabilities ve info olmak üzere gerekli bilgileri ayrı bir dictionary'e alıyoruz
                vulnerabilities["scans"].append(scan_json) #önceden oluşturduğumuz dictionary'nin scan key'ine sonuçları ekliyoruz
            return vulnerabilities
        else:
            vulnerabilities = {"scans": []} #boş bir dictionary oluşturuyoruz
            for scan in [x for x in self.get_all_results()["scans"] if x["scan-id"] == str(scan_id)]: #tüm sonuçlarda, scan-id'si parametre olarak gönderilen scan-id'ye eşit olan değerleri geziyoruz
                scan_json = {"scan-id": (scan["scan-id"]), "vulnerabilities": scan["details"]["vulnerabilities"],
                             "info": scan["details"]["info"]} #scan-id, vulnerabilities ve info olmak üzere gerekli bilgileri ayır bir dictionary'e alıyoruz
                vulnerabilities["scans"].append(scan_json) #önceden oluşturduğumuz dictionary'nin scan key'ine sonuçları ekliyoruz
            return vulnerabilities

    #sonuçları JSON formatında dosyaya yazmak için kullanacağımız fonksiyon
    def save_json(self, json_output, name:str):
        #eğer name değişkeniyle birlikte uzantı eklenmediyse dosyaya uzantı eklyoruz
        if ".json" not in name:
            name += ".json"
        #dosya yazma işlemlerini uyguluyoruz
        with open(name, "w") as output:
            output.write(json.dumps(json_output, indent=4, sort_keys=True)) #indent=4 ve sort_keys=True değerleri pretty text için önemli


#Nsc sınıfından bir obje yaratıyoruz
nessus_script = Nsc()
#Oluşturulan obje üzerinden ilgili işlemleri yaparak dosya olarak çıktı alacağımız fonskiyonları çağırıyoruz
nessus_script.save_json(nessus_script.get_all_results(), "output/all-scans.json")
nessus_script.save_json(nessus_script.get_vulnerabilities(), "output/vulnerabilities.json")
nessus_script.save_json(nessus_script.get_vulns_with_info(), "output/vulns-with-info.json")

