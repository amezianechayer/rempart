package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Lang is a covered language of the request (ADR 0006, amendment A1.1).
type Lang string

// Covered languages.
const (
	LangFR Lang = "fr"
	LangEN Lang = "en"
)

// Reasons of an unsupported language (closed list, plan P6).
const (
	ReasonAlphabet   = "alphabet"
	ReasonNoEvidence = "no_evidence"
	ReasonSentence   = "sentence"
)

// LanguageReport is the result of DetectLanguage.
type LanguageReport struct {
	Languages   []Lang // covered languages with non-zero evidence, sorted, no duplicate
	Primary     Lang   // language of the questions; "" if Unsupported
	Unsupported bool
	Reason      string // "" if covered, else one of the reasons above
}

// frenchLetters are the non-ASCII letters admitted (plan P3).
const frenchLetters = "àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ"

// Closed lists of plan sections 6.2 and 6.3, amended by V1.2. Any change
// needs a plan amendment and a security review.
var (
	// functionWords: frequent words of one covered language that are not
	// frequent words of a close uncovered language.
	functionWords = map[Lang]map[string]bool{
		LangFR: set(
			// grammar
			"les", "des", "du", "une", "et", "est", "sont", "ont", "pour", "sur", "dans", "avec", "sans", "je",
			"nous", "vous", "pas", "au", "aux", "ce", "cette", "ces", "cet", "par", "leur", "leurs", "notre",
			"votre", "vos", "veux", "voulons", "voudrais", "voudrions", "souhaite", "souhaitons", "faut", "doit",
			"doivent", "être", "avoir", "depuis", "vers", "chez", "très", "aussi", "elle", "elles", "ils", "sa",
			"ses", "mon", "mes", "ton", "tes", "tout", "tous", "toute", "toutes", "plus", "moins", "comme", "où",
			"quand", "dont", "bien", "peut", "peuvent", "pouvons", "pourra", "fait", "faire", "avons", "avez",
			"était", "sera", "seront", "été", "cela", "ça", "ceci", "celui", "celle", "ceux", "aucun", "aucune",
			"autre", "autres", "même", "encore", "déjà", "sous", "après", "avant", "pendant", "selon", "afin",
			"ainsi", "alors", "donc", "car", "puis", "chaque", "quelque", "quelques", "plusieurs", "lequel",
			"laquelle", "lesquels", "dès", "contre", "auprès", "parmi", "hors", "soit", "soient", "oui", "ici",
			"là", "lui", "eux", "moi", "toi", "derrière", "devant", "besoin", "merci", "aimerais", "uniquement",
			"seulement", "jamais", "toujours", "trois", "deux", "quatre", "cinq", "dix", "cent", "mille",
			// requests and infrastructure
			"données", "client", "clients", "clientes", "serveur", "serveurs", "réseau", "réseaux", "accès",
			"taille", "noeuds", "nœuds", "répartiteur", "charge", "relie", "relier", "porte", "portent",
			"soumis", "soumise", "soumises", "rester", "reste", "restent", "conformité", "mois", "région",
			"régions", "autorisé", "autorisée", "autorisés", "autorisées", "contrôleur", "journaux", "managé",
			"managée", "géré", "gérée", "consignes", "consigne", "précédent", "précédente", "précédents",
			"précédentes", "ignorez", "oublie", "oubliez", "rends", "rendez", "rendre", "mettre", "mets",
			"mettez", "sauvegarde", "sauvegardes", "stockage", "stocker", "stockées", "stockés", "hébergement",
			"héberger", "héberge", "équipe", "projet", "sécurité", "sécurisé", "sécurisée", "privé", "privée",
			"métriques", "tableaux", "bord", "rétention", "jours", "déployer", "déployé", "déployée", "machines",
			"virtuelle", "virtuelles", "applicatif", "applicative", "dossiers", "médicaux", "médicales",
			"utilisateurs", "utilisateur", "entreprise", "nouveau", "nouvelle", "ancien", "ancienne", "logs",
		),
		LangEN: set(
			// grammar
			"the", "and", "of", "to", "for", "with", "is", "are", "be", "we", "our", "want", "need", "needs",
			"must", "should", "this", "that", "these", "those", "from", "by", "at", "it", "its", "not", "or",
			"as", "into", "will", "can", "which", "on", "has", "have", "using", "without", "behind", "over",
			"he", "you", "do", "but", "his", "they", "say", "her", "she", "my", "one", "all", "would", "there",
			"their", "what", "up", "out", "if", "about", "who", "get", "go", "when", "make", "like", "just",
			"him", "know", "take", "people", "your", "good", "some", "could", "them", "see", "other", "than",
			"then", "now", "only", "think", "also", "back", "after", "use", "two", "how", "work", "first",
			"well", "way", "even", "new", "because", "any", "give", "most", "us", "was", "were", "been", "had",
			"does", "did", "each", "every", "both", "such", "through", "under", "within", "across", "where",
			"why", "while", "more", "less", "very", "here", "please", "let", "keep", "put", "three", "four",
			"five", "ten", "hundred", "thousand", "only", "old", "same", "between", "until", "outside",
			"inside", "never", "always",
			// requests and infrastructure
			"data", "customer", "customers", "user", "users", "server", "servers", "host", "hosts", "hosting",
			"node", "nodes", "size", "sized", "network", "networks", "connect", "connects", "connected",
			"connection", "ports", "month", "monthly", "region", "regions", "compliant", "controller", "legacy",
			"subject", "stay", "stays", "managed", "manage", "previous", "reachable", "available", "allowed",
			"allow", "storage", "store", "stored", "backup", "backups", "log", "logs", "metrics", "monitoring",
			"retention", "days", "load", "balancer", "request", "requests", "policy", "secure", "security",
			"private", "team", "project", "deploy", "deployed", "deployment", "run", "runs", "running", "set",
			"add", "build", "create", "provide", "support", "include", "includes", "including", "records",
			"record", "company", "owned", "located", "storing",
		),
	}
	// neutralWords: recognized words that are neither French nor English
	// evidence (V1.1): technical identifiers and words shared by the two
	// covered languages.
	neutralWords = set(
		"kubernetes", "k8s", "cluster", "clusters", "vm", "vms", "vpn", "waf", "gitops", "api", "dns", "tls",
		"ssl", "cdn", "ip", "iam", "ssh", "rdp", "lb", "saas", "paas", "iaas", "devops", "siem", "git", "redis",
		"kafka", "nginx", "docker", "opentofu", "terraform", "euros", "eur", "budget", "app", "apps",
		"application", "applications", "service", "services", "site", "sites", "instance", "instances",
		"machine", "patients", "accessible", "ignore", "compliance", "mode", "action", "test", "tests",
		"stack", "backend", "frontend", "port", "dashboards", "dashboard", "cloud", "clouds",
	)
	// zeroWeight: words shared with a close uncovered language (V1.1). They
	// count neither as recognized nor as foreign.
	zeroWeight = set(
		"in", "per", "le", "la", "de", "en", "un", "da", "di", "si", "se", "ne", "ma", "no", "non", "qui",
		"que", "nos", "ou", "mais", "entre", "via", "es", "son", "al", "an", "am", "so", "me", "te", "do",
		"lo", "come", "va",
	)
	// foreignSentinels: frequent words of uncovered languages (V1.2), an
	// additional signal; the proportion rule is the main guard.
	foreignSentinels = set(
		// Spanish
		"el", "los", "las", "del", "una", "con", "para", "por", "quiero", "necesito", "datos", "unos",
		"unas", "pero", "como", "esta", "este", "estos", "esto", "muy", "tambien", "nuestro", "nuestra",
		"nuestros", "nuestras", "servidor", "servidores", "desde", "hasta", "sobre", "porque", "cuando",
		"donde", "hay", "tiene", "tienen", "puede", "pueden", "debe", "deben", "ser", "estar", "sin",
		"queremos", "necesitamos",
		// Italian
		"il", "gli", "della", "delle", "dello", "degli", "dei", "che", "sono", "voglio", "dati", "nel",
		"nella", "nei", "nelle", "su", "sul", "sulla", "dal", "dalla", "anche", "questo", "questa", "questi",
		"essere", "abbiamo", "vogliamo", "serve", "servono", "molto", "tutti", "tutto", "ogni", "senza",
		"dopo", "prima", "tre", "deve", "devono", "cui", "quale", "ancora", "vorrei",
		// Portuguese
		"uma", "em", "quero", "dados", "preciso", "muito", "nossos", "nossa", "nosso", "pelo", "pela",
		"seu", "sua", "ao", "aos", "foi", "precisamos",
		// German
		"der", "die", "und", "mit", "ich", "nicht", "ist", "ein", "eine", "einen", "einem", "einer", "zu",
		"von", "auf", "wir", "soll", "sollen", "daten", "dem", "den", "sie", "sind", "wird", "werden",
		"auch", "aus", "bei", "nach", "noch", "nur", "oder", "sich", "sein", "unser", "unsere", "unseren",
		"unserer", "brauchen", "kein", "keine", "für", "über", "zum", "zur", "im", "vom", "beim", "drei",
		"zwei", "hat", "haben", "kann", "muss", "dass", "wenn", "wie", "wo", "hier", "jetzt", "alle",
		"viele", "ohne", "gegen", "bitte",
		// Dutch
		"het", "een", "ik", "wil", "voor", "niet", "wij", "gegevens", "naar", "zijn", "hebben", "wordt",
		"worden", "ook", "maar", "deze", "dit", "onze", "ons", "moet", "moeten", "kunnen", "graag", "bij",
		"uit", "nodig",
	)
	// foreignBigrams: sequences of two words of an uncovered language whose
	// words alone collide with a covered language.
	foreignBigrams = [][2]string{{"per", "i"}}

	// evidence: function words and one-word lexicon forms, per language;
	// recognized: every recognized word (evidence, neutral, any forms).
	evidence   = map[Lang]map[string]bool{}
	recognized = map[string]bool{}
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func init() {
	for _, l := range []Lang{LangFR, LangEN} {
		evidence[l] = map[string]bool{}
		for w := range functionWords[l] {
			evidence[l][w] = true
			recognized[w] = true
		}
	}
	for w := range neutralWords {
		recognized[w] = true
	}
	add := func(f forms) {
		for _, x := range [...]struct {
			dst  map[string]bool
			list []string
		}{{evidence[LangFR], f.fr}, {evidence[LangEN], f.en}, {nil, f.any}} {
			for _, form := range x.list {
				for _, w := range tokenize(form) {
					recognized[w] = true
				}
				if ws := tokenize(form); len(ws) == 1 && x.dst != nil {
					x.dst[ws[0]] = true
				}
			}
		}
	}
	for _, d := range []lexDomain{
		lexCloud, lexEnvironment, lexCriticality, lexTier, lexOS, lexProtocol, lexClass,
		lexRegulation, lexResidency, lexCompliance, lexObservability,
	} {
		for _, f := range d {
			add(f)
		}
	}
	add(databaseMarkers)
	add(exposureMarkers)
}

// inBlock reports the obfuscation blocks refused by V1.3: Letterlike Symbols,
// Enclosed Alphanumerics, Enclosed Alphanumeric Supplement (with the regional
// indicators).
func inBlock(r rune) bool {
	return r >= 0x2100 && r <= 0x214F || r >= 0x2460 && r <= 0x24FF || r >= 0x1F100 && r <= 0x1F1FF
}

// admittedRune: plan P3 and V1.3.
func admittedRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return true
	case inBlock(r):
		return false
	case unicode.In(r, unicode.Cc, unicode.Mn, unicode.Me, unicode.Cf, unicode.Co, unicode.Cs):
		return false
	case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z):
		return false // unassigned
	case unicode.IsLetter(r):
		return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || strings.ContainsRune(frenchLetters, r)
	case unicode.IsNumber(r):
		return r >= '0' && r <= '9'
	}
	return true
}

// wordJoiners may sit between two letters (V1.3): hyphen, apostrophes, and
// the dot (a sentence boundary for the detection, V1.4).
const wordJoiners = "-'\u2019."

// admittedText: plan P3 and V1.3, on the raw text.
func admittedText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	prev := rune(0)
	for i, r := range text {
		if !admittedRune(r) {
			return false
		}
		if unicode.In(r, unicode.P, unicode.S) && !strings.ContainsRune(wordJoiners, r) && unicode.IsLetter(prev) {
			if next, _ := utf8.DecodeRuneInString(text[i+utf8.RuneLen(r):]); unicode.IsLetter(next) {
				return false
			}
		}
		prev = r
	}
	return true
}

// detectionSentences: the split of sentences (P4) plus a dot followed by a
// letter, \r and the separators Zl and Zp (V1.4). Variant D keeps sentences.
func detectionSentences(text string) []string {
	var out []string
	start := 0
	for i, r := range text {
		cut := false
		switch {
		case strings.ContainsRune("!?;\n\r", r), unicode.In(r, unicode.Zl, unicode.Zp):
			cut = true
		case r == '.':
			next, _ := utf8.DecodeRuneInString(text[i+1:])
			cut = i+1 == len(text) || unicode.IsSpace(next) || unicode.IsLetter(next)
		}
		if cut {
			out = append(out, text[start:i])
			start = i + utf8.RuneLen(r)
		}
	}
	return append(out, text[start:])
}

func isWord(tok string) bool {
	for _, r := range tok {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return utf8.RuneCountInString(tok) >= 2
}

// langCounts: fr and en evidence; n: words of two letters or more without
// zero weight; ev: recognized ones among them; foreign: sentinels.
type langCounts struct{ fr, en, n, ev, foreign int }

func count(text string) langCounts {
	var c langCounts
	toks := tokenize(text)
	for i, tok := range toks {
		if evidence[LangFR][tok] {
			c.fr++
		}
		if evidence[LangEN][tok] {
			c.en++
		}
		if foreignSentinels[tok] {
			c.foreign++
		}
		for _, b := range foreignBigrams {
			if tok == b[0] && i+1 < len(toks) && toks[i+1] == b[1] {
				c.foreign++
			}
		}
		if isWord(tok) && !zeroWeight[tok] {
			c.n++
			if recognized[tok] {
				c.ev++
			}
		}
	}
	return c
}

// DetectLanguage: plan P3 to P6 and amendment V1. Deterministic, linear in the
// size of the text. It reads only the user's text.
func DetectLanguage(text string) LanguageReport {
	unsupported := func(reason string) LanguageReport { return LanguageReport{Unsupported: true, Reason: reason} }
	if !admittedText(text) {
		return unsupported(ReasonAlphabet)
	}
	total := count(text)
	if total.fr+total.en == 0 {
		return unsupported(ReasonNoEvidence)
	}
	for _, s := range detectionSentences(text) {
		c := count(s)
		if c.n >= 3 && c.n-c.ev > c.ev || c.foreign > c.ev {
			return unsupported(ReasonSentence)
		}
	}
	var rep LanguageReport
	if total.en > 0 {
		rep.Languages = append(rep.Languages, LangEN)
	}
	if total.fr > 0 {
		rep.Languages = append(rep.Languages, LangFR)
	}
	rep.Primary = LangFR
	if total.en > total.fr {
		rep.Primary = LangEN
	}
	return rep
}
