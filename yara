rule detect_phishing_campaign {
    meta:
        description = "Detects a phishing campaign targeting the Medios and insurance sector"
        author = "Fevar54"
        date = "2023-03-11"
    strings:
        $domain1 = "apple-icloud-mx.com"
        $domain2 = "apple-icloud-us.com"
        $domain3 = "apple-encontrar-icloud.com"
    condition:
        domain in {$domain1 $domain2 $domain3} and
        all of them
