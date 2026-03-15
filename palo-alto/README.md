WARNING: Everything in this Folder is untested!

# Short Scripts

Super short curl versions
```
curl -k -X POST "https://172.20.242.150/api/" \
  -d "type=keygen&user=admin&password=Changeme123"
```
Then:
```
curl -k -H "X-PAN-KEY: YOUR_KEY_HERE" \
  "https://172.20.242.150/api/?type=export&category=configuration" \
  -o palo_running_export.xml
```
And:
```
curl -k -H "X-PAN-KEY: YOUR_KEY_HERE" \
  "https://172.20.242.150/api/?type=config&action=show" \
  -o palo_active_config_response.xml
```


# Open PowerShell as Administrator:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install_python_and_requests.ps1
```

# Nice combined flow for CCDC

A practical sequence on the Windows box would be:
```
.\install_python_and_requests.ps1
python .\pa_export_config_file.py
.\upload_backup.ps1 -FilePath ".\palo_running_export.xml" -UploadUrl "https://YOURBOX/upload" -ApiToken "TOKEN"
Important note
```

