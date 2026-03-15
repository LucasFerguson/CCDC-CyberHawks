

# NextCloud

Uploading files from env to NextCloud

Request full upload link from  automated chat bot 

Note: "Obviously you shouldn't be pulling everything out of the env. And all uploads using the link are read-only in Nextcloud so that they can be audited by white team during the event." - Jimmy

So the flow should be
- upload file using link -> download file to local machine to work on it -> upload to nextcloud/NISE as needed

```
curl -T <filename> -u "<link_code>:" -H 'X-Requested-With: XMLHttpRequest' https://docs.ccdc.events/public.php/dav/files/<link_code>/<filename>
```

So if you want to upload text.txt and your team's upload link is docs.ccdc.events/s/asdf1234asdf4321

```
curl -T test.txt -u "asdf1234asdf4321:" -H 'X-Requested-With: XMLHttpRequest' https://docs.ccdc.events/public.php/dav/files/asdf1234asdf4321/test.txt
```
