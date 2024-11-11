##DNS

### Push DNS

Pour faire un push DNS : 
```
nsupdate
> server <IP CIBLE DNS>
> update add txt.beerus.fr 60 IN TXT "blabla"
> update add toto.beerus.fr 60 IN A 4.5.6.7
> send
```

## Prometheus

### Supprime metrics

Pour supprimer des metrics qui prennent de la place : 

```shell
[root@trump docker]# curl -X POST -g 'http://<IP>:9090/api/v1/admin/tsdb/delete_series?match[]=up&match[]=container_network_advance_tcp_stats_total'
[root@trump docker]# du -sh src/prometheus/
421M    src/prometheus/
[root@trump docker]# curl -XPOST http://<IP>:9090/api/v1/admin/tsdb/clean_tombstones
[root@trump docker]# du -sh src/prometheus/
294M    src/prometheus/
[root@trump docker]#
```

##VSCode

Markdown: Open Preview to the Side command (Ctrl+K V).
