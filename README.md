Something to check the expiration of SSL certs and send alerts to slack.

```
certs_check -hosts host1.example.com:443,host2.example.com:443 -webhook-url https://your.slack.webhook
```
