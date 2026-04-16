package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
)

// ReadRequest reads an HTTP request from the given reader.
func ReadRequest(r io.Reader) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(r))
}

// ExtractOrigin extracts the scheme and host from the request to form an origin.
// If the scheme is missing, it defaults to "https".
func ExtractOrigin(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	// Extract host without port for origin
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	if host == "" {
		// Fallback to header
		host = req.Header.Get("Host")
	}

	// Remove port from host for origin
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port in host
		hostname = host
	}

	return scheme + "://" + hostname
}

// InjectCookies adds the given cookies to the request's Cookie header.
func InjectCookies(req *http.Request, cookies []*http.Cookie) {
	if len(cookies) == 0 {
		return
	}

	var cookieStrs []string
	for _, c := range cookies {
		cookieStrs = append(cookieStrs, c.Name+"="+c.Value)
	}

	existing := req.Header.Get("Cookie")
	if existing != "" {
		cookieStrs = append(cookieStrs, existing)
	}

	req.Header.Set("Cookie", strings.Join(cookieStrs, "; "))
}

// Send sends the HTTP request and returns the response.
func Send(req *http.Request) (*http.Response, error) {
	// Clear RequestURI since it's set by http.ReadRequest but can't be used in client requests
	req.RequestURI = ""

	// Ensure the URL is properly set from the host and path
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	client := &http.Client{}
	return client.Do(req)
}

// SeparateSetCookies splits Set-Cookie headers into HttpOnly and non-HttpOnly cookies.
// It returns the non-HttpOnly cookies to be returned in the response, and HttpOnly cookies
// to be saved to the cookie jar only.
func SeparateSetCookies(resp *http.Response) ([]*http.Cookie, []*http.Cookie) {
	var nonHttpOnly, httpOnly []*http.Cookie

	for _, setCookieHeader := range resp.Header.Values("Set-Cookie") {
		c := parseCookie(setCookieHeader)
		if c.HttpOnly {
			httpOnly = append(httpOnly, c)
		} else {
			nonHttpOnly = append(nonHttpOnly, c)
		}
	}

	return nonHttpOnly, httpOnly
}

// StripHttpOnlySetCookies removes all Set-Cookie headers with the HttpOnly flag
// and returns a new response with the non-HttpOnly Set-Cookie headers preserved.
func StripHttpOnlySetCookies(resp *http.Response) *http.Response {
	nonHttpOnly, _ := SeparateSetCookies(resp)

	// Clear all Set-Cookie headers
	resp.Header.Del("Set-Cookie")

	// Add back only non-HttpOnly cookies
	for _, c := range nonHttpOnly {
		resp.Header.Add("Set-Cookie", c.String())
	}

	return resp
}

// WriteResponse writes the HTTP response to the given writer.
func WriteResponse(w io.Writer, resp *http.Response) error {
	return resp.Write(w)
}

// parseCookie parses a Set-Cookie header value into an http.Cookie.
// This is a simplified parser that handles the basic cookie attributes.
func parseCookie(setCookie string) *http.Cookie {
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		return &http.Cookie{}
	}

	// First part is name=value
	nameValue := strings.TrimSpace(parts[0])
	idx := strings.Index(nameValue, "=")
	var name, value string
	if idx >= 0 {
		name = strings.TrimSpace(nameValue[:idx])
		value = strings.TrimSpace(nameValue[idx+1:])
	} else {
		name = nameValue
	}

	c := &http.Cookie{
		Name:  name,
		Value: value,
	}

	// Parse attributes
	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		attrParts := strings.Split(part, "=")
		attrName := strings.TrimSpace(attrParts[0])

		switch strings.ToLower(attrName) {
		case "path":
			if len(attrParts) > 1 {
				c.Path = strings.TrimSpace(attrParts[1])
			}
		case "domain":
			if len(attrParts) > 1 {
				c.Domain = strings.TrimSpace(attrParts[1])
			}
		case "expires":
			if len(attrParts) > 1 {
				// Parse expires (RFC 1123 format) - simplified
				c.RawExpires = strings.TrimSpace(attrParts[1])
			}
		case "max-age":
			if len(attrParts) > 1 {
				// Parse max-age - let Go's http package handle this
				c.RawExpires = strings.TrimSpace(attrParts[1])
			}
		case "secure":
			c.Secure = true
		case "httponly":
			c.HttpOnly = true
		case "samesite":
			if len(attrParts) > 1 {
				c.SameSite = parseSameSite(strings.TrimSpace(attrParts[1]))
			}
		}
	}

	return c
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(value) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
