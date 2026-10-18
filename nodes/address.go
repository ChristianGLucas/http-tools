package nodes

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// A per-account address (0.9.0). Some providers give every account its own API
// host (Infobip: https://{account}.api.infobip.com; a Shopify shop, a Zendesk
// subdomain). The person stores that address as a secret, like a key, and the
// Instance names it in address_secret_name; `url` is then only a path. The
// address is the person's: neither the Instance's author nor a caller can
// choose it, so a key attached to the request goes only to the host the person
// gave. The node checks the address before any key is read (research: platforms
// that store a host with a credential validate it at connect time and attach
// the key only for that host; secret-injecting egress proxies refuse private,
// loopback, link-local and metadata addresses, which the dial guard below does
// for every request).

// urlProblem is a problem with the request URL found before anything is sent:
// a typed transport failure (code), or, when hard, an error in the graph that
// fails the node whatever typed_errors says (a missing secret, like a missing
// auth secret).
type urlProblem struct {
	code string
	err  error
	hard bool
}

func urlFail(code, format string, args ...any) *urlProblem {
	return &urlProblem{code: code, err: fmt.Errorf(format, args...)}
}

// hostLabel is one DNS label: ASCII letters, digits and inner hyphens.
var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// internalSuffixes are names that never point at a public service.
var internalSuffixes = []string{"localhost", "local", "internal", "localdomain", "lan", "intranet", "home.arpa"}

// checkAddress returns the canonical address (scheme, host and any base path,
// with no trailing slash) or why it is not a public https address. The reason
// never repeats the address: it is a secret's value.
func checkAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("it is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("it is not a web address")
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("it must start with https://")
	}
	if u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("it has no host name")
	}
	if u.User != nil {
		return "", fmt.Errorf("it carries a user name or password")
	}
	if u.Port() != "" || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("it names a port")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("it has a query or a fragment")
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || strings.HasPrefix(u.Host, "[") {
		return "", fmt.Errorf("it is an IP address, not a host name")
	}
	if strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("its host name ends with a dot")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("its host name is not a public domain name")
	}
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return "", fmt.Errorf("its host name is not a plain domain name")
		}
	}
	if !strings.ContainsAny(labels[len(labels)-1], "abcdefghijklmnopqrstuvwxyz") {
		return "", fmt.Errorf("its host name is not a public domain name")
	}
	for _, s := range internalSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "", fmt.Errorf("its host name is an internal one")
		}
	}
	return "https://" + host + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// resolveRequestURL is the URL the request goes to: `url` as given, or, with
// address_secret_name, the person's address followed by `url` as a path.
func resolveRequestURL(ax axiom.Context, input *gen.HttpRequest) (*url.URL, *urlProblem) {
	rawURL := strings.TrimSpace(input.GetUrl())
	name := strings.TrimSpace(input.GetAddressSecretName())
	if name != "" {
		return addressURL(ax, name, rawURL)
	}
	if rawURL == "" {
		return nil, urlFail("INVALID_URL", "url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, urlFail("INVALID_URL", "invalid url %q: %v", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, urlFail("INVALID_URL", "unsupported url scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return nil, urlFail("INVALID_URL", "url %q has no host", rawURL)
	}
	return u, nil
}

func addressURL(ax axiom.Context, name, path string) (*url.URL, *urlProblem) {
	// The path is checked first: it never reads the secret, and an absolute url
	// (a host the address does not decide) is never sent with an address.
	if path != "" && !strings.HasPrefix(path, "/") {
		return nil, urlFail("INVALID_URL", "with address_secret_name, url is a path that starts with \"/\" (the "+
			"address %s holds decides the host), not %q", name, path)
	}
	raw, ok := ax.Secrets().Get(name)
	if !ok {
		return nil, &urlProblem{code: "SECRET_NOT_SET", err: fmt.Errorf("required secret %q is not configured", name), hard: true}
	}
	base, err := checkAddress(raw)
	if err != nil {
		return nil, urlFail("ADDRESS_INVALID", "the address in %s is not a public https address: %v", name, err)
	}
	u, perr := url.Parse(base + path)
	want, _ := url.Parse(base)
	// The composed URL keeps the address's host whatever the path holds; anything
	// else is refused rather than sent.
	if perr != nil || u.Scheme != "https" || u.User != nil || !strings.EqualFold(u.Host, want.Host) {
		return nil, urlFail("INVALID_URL", "url %q does not make a request to the address in %s", path, name)
	}
	return u, nil
}
