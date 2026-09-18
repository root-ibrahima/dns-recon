# dns-recon

**DNS Subdomain Enumeration Tool** écrit en Go. Scanner de reconnaissance active pour découvrir les subdomaines d'un domaine cible via bruteforce DNS. Utile pour les phases initiales de pentesting / OSINT, quand tu dois mapper l'infrastructure exposée d'une cible.

## Pourquoi c'est différenciant

- **Concurrence efficace** : Le tool utilise un **worker pool pattern** (goroutines + buffered channels + WaitGroup) pour résoudre en parallèle plusieurs subdomains sans bloquer sur les DNS lents ou timeouts. C'est un standard en Go.
- **Pas de dépendances externes** : Utilise uniquement `net` et la stdlib Go — pas de cliente DNS tiers, pas de librairie OSINT. C'est petit, rapide, portable.
- **Timeout par lookup** : Chaque résolution DNS a un timeout configurable (`-timeout`), ce qui évite d'attendre indéfiniment sur des domaines qui ne répondent pas.
- **Structures JSON-friendly** : Chaque `Record` et `Result` est prête pour json.Marshal, utile pour pipeline CI ou autre outil.
- **Gestion d'erreurs intelligente** : Les timeouts sont loggés, les NXDOMAIN sont silencieux (normal, pas une erreur), les vrais problèmes remontent.

## Concepts Go démontrés

### 1. **Worker Pool Pattern** (concurrence maîtrisée)

```go
jobs := make(chan string, opts.Workers)  // buffered channel
results := make(chan Record)
var wg sync.WaitGroup

for i := 0; i < opts.Workers; i++ {
    wg.Add(1)
    go resolveWorker(&wg, domain, jobs, results, errors, opts)
}

// Spawn sender
go func() {
    for _, subdomain := range subdomains {
        jobs <- subdomain  // Worker plucks from this channel
    }
    close(jobs)  // Signal workers that no more jobs coming
}()

wg.Wait()  // Blocks until all Add(1) calls matched Done()
```

**Pourquoi c'est utile** : Tu ne crées pas une goroutine par subdomain (débordement mémoire si 1M subdomains). Tu crées N workers (ex: 10) et tu les réutilises. C'est le pattern qu'utilisent les vrais outils (Masscan, Aquatone, Subfinder).

### 2. **Context avec timeout** (pas de goroutines qui traînent)

```go
ctx, cancel := context.WithTimeout(context.Background(), timeout)
defer cancel()

resolver := &net.Resolver{PreferGo: true}
ips, err := resolver.LookupHost(ctx, fqdn)
```

**Pourquoi** : Si le serveur DNS du système est complètement down, LookupHost peut bloquer longtemps (selon le système d'exploitation). Context + timeout évite ça.

### 3. **Select sur channels** (gérer plusieurs signaux)

```go
for {
    select {
    case record, ok := <-results:
        if !ok { return result }  // Channel fermé
        result.Records = append(result.Records, record)
    case err := <-errors:
        result.Errors = append(result.Errors, err)
    case <-done:
        // Signal que tous les workers ont fini
    }
}
```

**Pourquoi** : Tu attends en même temps sur results, errors, et done. Pas de polling, pas de busy-wait.

### 4. **Struct embedding pour la composition** (pas d'héritage)

```go
type Result struct {
    Domain    string
    Records   []Record
    Stats     Stats       // Stats est une struct imbriquée
    Errors    []string
}

// Lors du json.Marshal, Stats.Duration devient "stats": {"duration": ...}
```

### 5. **Interfaces implicites** (duck typing)

```go
func Terminal(stderr, out io.Writer, result resolver.Result) {
    fmt.Fprintf(out, ...)  // Fonctionne avec *os.File, *bytes.Buffer, etc.
}
```

N'importe quoi qui implémente Write([]byte) satisfait io.Writer. Pas besoin de déclarer "j'implémente io.Writer".

## Installation & Build

```bash
git clone <ce repo>
cd dns-recon
go build -o dns-recon .
```

## Configuration

Pas d'authentification requise (c'est juste du DNS public). Besoin d'une connexion réseau pour faire les résolutions.

## Utilisation

### Scan basique

```bash
./dns-recon -domain example.com
```

Utilise les 10 workers par défaut, 5s timeout, wordlist `wordlists/common.txt`, affiche en couleur.

### Avec custom wordlist

```bash
./dns-recon -domain example.com -wordlist /path/to/wordlist.txt
```

### Plus de workers (plus rapide, mais plus agressif)

```bash
./dns-recon -domain example.com -workers 50
```

### Export JSON (pour pipeline)

```bash
./dns-recon -domain example.com -format json -output recon.json
```

Utile pour :
- Piping vers jq/python pour post-traitement
- Archiver les résultats
- Intégrer dans un scanner multi-étapes

### Timeout plus court (pour domaines rapides)

```bash
./dns-recon -domain example.com -timeout 2s
```

## Structure du code

```
main.go                          # CLI: flags, orchestration
internal/resolver/
  resolver.go                    # Enumerate, worker pool, DNS lookups
internal/report/
  report.go                      # Terminal (colors) et JSON output
wordlists/
  common.txt                     # ~100 subdomains courants
go.mod                           # Dépendances (aucune!)
README.md                        # Ce fichier
```

## Limites connues (à mentionner en entretien)

- **Pas de wildcard detection** : Si `*.example.com` pointe vers une IP, on va lister bcp de faux positifs. À améliorer avec une détection / filtering.
- **Pas de résolution CNAME** : On récupère juste les A records. Les CNAME sont ignorés. À ajouter en v2.
- **Pas de brute-force parallèle par resolver** : On utilise le resolver système (récursif via `/etc/resolv.conf`). Un vrai outil ferait des requêtes directes sur les authoritative nameservers pour plus de control/parallélisme.
- **Pas de validation DNSSEC** : On fait confiance à ce que le DNS répond.
- **Wordlist taille fixe** : Plus la wordlist est grande, plus long le scan. Trade-off speed vs coverage.

## Concepts à expliquer en entretien

1. **Pourquoi les goroutines et pas les threads ?**
   - Goroutines = plus légères, context-switch moins cher, scheduler Go a du control.
   - Threads OS = lourd (1+ MB par thread), plus lent à switcher.
   - Avec 10 goroutines tu caches ~10 DNS latencies en même temps. Avec threads c'est la même mais tu consommes bcp plus de RAM.

2. **Pourquoi buffered channels sur les jobs ?**
   - Si tu utilises `jobs := make(chan string)` (non-buffered), le sender bloque après chaque send jusqu'à ce qu'un worker reçoive.
   - Avec `make(chan string, opts.Workers)` c'est un buffer de taille N, donc le sender peut mettre N jobs d'avance sans bloquer. Maximise parallélisme.

3. **Comment tu gères la mémoire avec 1M subdomains ?**
   - Tu ne charges pas 1M à la fois si tu n'as pas de RAM. Tu lis ligne par ligne du wordlist (bufio.Scanner).
   - Tu gardes les workers à un nombre constant (10), pas un par subdomain.
   - Les results accumulent dans la slice `result.Records`, donc oui ça grandit. Mais tu peux la flusher à la volée (à améliorer).

4. **Et si un worker panic ?**
   - Actuellement rien, il crash le programme. À ajouter : recover() + log + continue.

## Améliorations futures

- [ ] Wildcard detection + filtering
- [ ] CNAME resolution
- [ ] Configurable output filters (ex: only IP ranges from corp)
- [ ] Rate limiting (DNS flooding protection)
- [ ] Recursive resolver au lieu du système
- [ ] Panic recovery in worker
- [ ] Streaming results to file (pas tout en mémoire)
- [ ] Stats per TLD / per resolver

---

**Utilité réelle** : Ce tool résout un vrai besoin en reconnaissance réseau. Il est assez simple pour être lisible en entretien, assez complet pour montrer de la maîtrise des patterns Go. Les concepts (concurrence, context, interfaces, JSON) reviennent partout dans les vrais projets.
