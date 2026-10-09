# Programarea mentenanței SQLite în VM-ul IDS

Fișierele din acest director pregătesc o sarcină cron zilnică la 03:15, în
fusul orar al VM-ului. Ele nu sunt instalate automat de Docker Compose.

Scriptul execută `maintenance.py cleanup` în containerul `reaction` deja
pornit și folosește `REACTION_DB_PATH` din mediul acestuia. Nu pornește un
al doilea serviciu de citire a alertelor. `flock` împiedică suprapunerea
rulărilor pornite prin această sarcină. Dacă nu există containerul activ,
comanda eșuează și eroarea rămâne în jurnal.

În VM trebuie să fie disponibile Docker la `/usr/bin/docker`, `flock` la
`/usr/bin/flock` și serviciul cron activ. Containerul trebuie să includă
versiunea actualizată a `maintenance.py` și pachetul `reaction_common`.

Din rădăcina `Proiect`, după sincronizarea fișierelor în VM:

```sh
sudo install -m 0755 reaction-service/ops/run-maintenance.sh /usr/local/sbin/ids-reaction-maintenance
sudo install -m 0644 reaction-service/ops/ids-reaction-maintenance.cron /etc/cron.d/ids-reaction-maintenance
```

Acestea sunt instrucțiuni de instalare pentru VM, nu comenzi executate în
workspace. Verificarea ulterioară se face în
`/var/log/ids-reaction-maintenance.log`. Jurnalul nu are rotație inclusă în
acest exemplu; trebuie integrat în politica de logrotate a gazdei.

Curățarea păstrează politica existentă: elimină cooldown-urile expirate,
marchează acțiunile expirate și șterge acțiunile în starea `expired` sau
`unblocked` mai vechi de 30 de zile, după data creării. Auditul are retenție
de 90 de zile. Încercările asociate acțiunilor șterse sunt eliminate prin
relația `ON DELETE CASCADE`.

Operația existentă readuce și acțiunile `processing` mai vechi de cinci
minute în `pending`, fără să verifice regulile din switch. După întreruperea
unei blocări/deblocări, verifică starea reală înainte de reconfirmare.
Programarea nu reprezintă un mecanism de reconciliere cu Floodlight.
