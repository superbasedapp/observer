package secdiffobs

import (
	"regexp"
	"strings"
)

// infer.go holds the regression inferences S-762 to S-766 (section 5.7).
// Each is a guess about intent, so each is flag-only; each has positive and
// near-miss rows in infer_test.go. A line whose identical text the same
// file both removes and adds is a move, never a hit; a comment line is
// never a hit.

// authCheck matches an authentication decorator or middleware line
// (S-762, removed).
var authCheck = regexp.MustCompile(`(@login_required\b|@permission_required\b|@requires_auth\b|@jwt_required\b|@auth_required\b|@authenticated\b|@Secured\(|@PreAuthorize\(|@RolesAllowed\(|\[Authorize\b|\brequireAuth\b|\bensureAuthenticated\b|\bisAuthenticated\b|passport\.authenticate\(|\bauthMiddleware\b|\bAuthMiddleware\b|\.use\(\s*auth\w*\s*[,)]|\bverifyToken\b|\bcheckAuth\b|authenticate_user!|before_action\s+:authenticate|permission_classes\s*=\s*\[\s*IsAuthenticated)`)

// authBypass matches an added line that switches an authentication check
// off (S-762, added).
var authBypass = regexp.MustCompile(`(?i)(\b(skip_?auth|bypass_?auth|auth_?disabled|disable_?auth|no_?auth)\b\s*[=:]\s*(true|1|"yes"|'yes')\b|permission_classes\s*=\s*\[\s*AllowAny\s*\]|authentication_classes\s*=\s*\[\s*\])`)

// debugCond matches a debug or development condition (S-763).
var debugCond = regexp.MustCompile(`(?i)\b(if|elif|when|unless)\b[^\n]*\b(debug|dev_mode|devmode|is_dev|development|local_dev)\b`)

// privilegedReturn matches a return of a privileged identity (S-763).
var privilegedReturn = regexp.MustCompile(`(?i)\breturn\b[^\n]*(["']?role["']?\s*[:=]\s*["'](admin|root|superuser|owner)["']|\bis_(admin|superuser|staff)["']?\s*[:=]\s*true\b|\b(admin|superuser)_?user\b|\bUser\(\s*["']?(admin|root)\b)`)

// csrfExempt matches a CSRF exemption (S-764, added).
var csrfExempt = regexp.MustCompile(`(@csrf_exempt\b|\bcsrf_exempt\(|WTF_CSRF_ENABLED\s*=\s*False\b|\.csrf\(\)\s*\.disable\(\)|\.csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|\bcsrf\s*:\s*false\b|@IgnoreAntiforgeryToken\b|\[IgnoreAntiforgeryToken\]|\bskip_forgery_protection\b|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session)`)

// corsAnyOrigin matches a wildcard CORS origin (S-765).
var corsAnyOrigin = regexp.MustCompile(`(?i)(access-control-allow-origin["']?\s*[:,]\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|\borigins?\s*[:=]\s*(true\b|["']\*["'])|cors_origin_allow_all\s*=\s*true|cors_allow_all_origins\s*=\s*true|AllowAnyOrigin\(\)|AllowedOrigins\s*[:=]\s*\[\]string\{\s*"\*"|AllowAllOrigins\s*[:=]\s*true)`)

// corsCredentials matches CORS credentials switched on (S-765).
var corsCredentials = regexp.MustCompile(`(?i)(allow_credentials\s*=\s*true|\bcredentials\s*:\s*true\b|access-control-allow-credentials["']?\s*[:,]\s*["']?true|cors_allow_credentials\s*=\s*true|AllowCredentials\s*(\(\s*\)|[:=]\s*true)|supports_credentials\s*=\s*true)`)

// rateLimit matches a rate limit (S-766, removed).
var rateLimit = regexp.MustCompile(`(@limiter\.limit\b|@ratelimit\b|@rate_limit\b|\brateLimit\(|\bRateLimit\(|express-rate-limit|\bthrottle_classes\b|@Throttle\b|\[EnableRateLimiting|\bRateLimiter\b|\blimiter\.(Wait|Allow)\(|\bslowDown\(|@RateLimiter\b|\brack-attack\b|Rack::Attack)`)

// isComment reports a line that is only a comment.
func isComment(text string) bool {
	t := strings.TrimSpace(text)
	for _, p := range []string{"#", "//", "/*", "*", "--", "<!--"} {
		if strings.HasPrefix(t, p) && !strings.HasPrefix(t, "#[") {
			return true
		}
	}
	return false
}

// hit is one inference hit.
type hit struct {
	rule string
	line int
}

// inferRegressions runs S-762 to S-766 over one file's change.
func inferRegressions(f FileDiff) []hit {
	var out []hit
	live := func(l Line) bool { return !isComment(l.Text) }
	for _, l := range f.Removed {
		if !live(l) || markerRemovedSame(l.Text, f.Added) {
			continue
		}
		if authCheck.MatchString(l.Text) {
			out = append(out, hit{"S-762", l.N})
		}
		if rateLimit.MatchString(l.Text) {
			out = append(out, hit{"S-766", l.N})
		}
	}
	originLine, origin, credentials := 0, false, false
	for i, l := range f.Added {
		if !live(l) || markerRemovedSame(l.Text, f.Removed) {
			continue
		}
		if authBypass.MatchString(l.Text) {
			out = append(out, hit{"S-762", l.N})
		}
		if debugCond.MatchString(l.Text) && privilegedNear(f.Added, i) {
			out = append(out, hit{"S-763", l.N})
		}
		if csrfExempt.MatchString(l.Text) {
			out = append(out, hit{"S-764", l.N})
		}
		if !origin && corsAnyOrigin.MatchString(l.Text) {
			origin, originLine = true, l.N
		}
		if corsCredentials.MatchString(l.Text) {
			credentials = true
		}
	}
	if origin && credentials {
		out = append(out, hit{"S-765", originLine})
	}
	return out
}

// privilegedNear reports a privileged return on the condition's own line
// or within the next three added lines, while they stay contiguous.
func privilegedNear(added []Line, i int) bool {
	for j := i; j < len(added) && j <= i+3; j++ {
		if j > i && added[j].N != added[j-1].N+1 {
			return false
		}
		if !isComment(added[j].Text) && privilegedReturn.MatchString(added[j].Text) {
			return true
		}
	}
	return false
}
