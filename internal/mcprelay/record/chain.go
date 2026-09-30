// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"strings"
)

// genesisDomain prefixes the genesis preimage (doc3 §3.2, R8.27.a/g):
// chain_prev of seq 1 = SHA-256("sbo-mcp-relay-genesis-v1" || node key).
const genesisDomain = "sbo-mcp-relay-genesis-v1"

// canonicalDomain prefixes every canonical encoding so a record hash can never
// collide with a genesis hash or a foreign chain's record.
const canonicalDomain = "sbo-mcp-relay-record-v1"

// Genesis returns the node's genesis head hash: the chain_prev of the first
// record. nodeKey is the node's stable identity (the per-device agent-access
// key thumbprint, or the machine fingerprint when no key exists yet).
func Genesis(nodeKey string) []byte {
	sum := sha256.Sum256([]byte(genesisDomain + nodeKey))
	return sum[:]
}

// HashRecord computes chain_hash = SHA-256(canonical || chainPrev).
func HashRecord(canonical, chainPrev []byte) []byte {
	h := sha256.New()
	h.Write(canonical)
	h.Write(chainPrev)
	return h.Sum(nil)
}

// Canonical returns the canonical encoding of r: every column except the two
// chain columns, in DDL order, as domain-prefixed "name=len:value\n" lines.
// The length prefix makes the encoding unambiguous for any value bytes; ""
// encodes a NULL text column and a nil pointer a NULL integer column, so the
// encoding is a function of the row AS STORED and re-reading the row
// reproduces it byte for byte.
func Canonical(r Record) []byte {
	var sb strings.Builder
	sb.WriteString(canonicalDomain)
	sb.WriteByte('\n')
	str := func(name, v string) {
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(strconv.Itoa(len(v)))
		sb.WriteByte(':')
		sb.WriteString(v)
		sb.WriteByte('\n')
	}
	num := func(name string, v *int64) {
		if v == nil {
			str(name, "")
			return
		}
		str(name, strconv.FormatInt(*v, 10))
	}
	str("seq", strconv.FormatInt(r.Seq, 10))
	str("record_kind", string(r.Kind))
	str("ts", strconv.FormatInt(r.TS, 10))
	str("family", r.Family)
	num("decision_seq", r.DecisionSeq)
	str("vserver", r.VServer)
	str("server_ref_hmac", r.ServerRefHMAC)
	str("tool_ref_hmac", r.ToolRefHMAC)
	str("server", r.Server)
	str("tool", r.Tool)
	str("call_id", r.CallID)
	str("trace_id", r.TraceID)
	str("coding_session_id", r.CodingSessionID)
	str("turn_ref", r.TurnRef)
	str("action_ref", r.ActionRef)
	str("corr_confidence", string(r.CorrConfidence))
	str("method", r.Method)
	str("event_kind", string(r.EventKind))
	str("decision", string(r.Decision))
	str("reason_code", r.ReasonCode)
	str("client_attestation", string(r.ClientAttestation))
	str("credential_assurance", r.CredentialAssurance)
	str("capture_level", string(r.CaptureLevel))
	str("args_excerpt", r.ArgsExcerpt)
	str("args_full", r.ArgsFull)
	str("args_scrub_status", string(r.ArgsScrubStatus))
	str("result_full", r.ResultFull)
	str("result_scrub_status", string(r.ResultScrubStatus))
	str("error_full", r.ErrorFull)
	str("error_scrub_status", string(r.ErrorScrubStatus))
	str("elicitation_full", r.ElicitationFull)
	str("elicitation_scrub_status", string(r.ElicitationScrubStatus))
	num("result_size_bytes", r.ResultSizeBytes)
	num("latency_ms", r.LatencyMS)
	str("result_status", r.ResultStatus)
	num("gap_from", r.GapFrom)
	num("gap_to", r.GapTo)
	num("lost_count", r.LostCount)
	str("gap_reason", r.GapReason)
	num("resolves_seq", r.ResolvesSeq)
	num("resolved_range_start", r.ResolvedRangeStart)
	num("resolved_range_end", r.ResolvedRangeEnd)
	str("resolution", string(r.Resolution))
	return []byte(sb.String())
}

// VerifyRecords walks records (which must be the WHOLE chain, seq ascending
// from 1) from genesis and returns the first fault: a non-contiguous seq, a
// chain_prev that does not equal the prior chain_hash, or a chain_hash that
// does not equal HashRecord(Canonical(row), chain_prev). An empty input
// verifies trivially with the genesis head.
func VerifyRecords(genesis []byte, records []Record) VerifyResult {
	res := VerifyResult{HeadSeq: 0, HeadHash: genesis}
	prev := genesis
	for i := range records {
		r := records[i]
		want := res.HeadSeq + 1
		if r.Seq != want {
			res.Fault = &Fault{Seq: r.Seq, Reason: "seq is not contiguous (want " + strconv.FormatInt(want, 10) + ")"}
			return res
		}
		if !bytes.Equal(r.ChainPrev, prev) {
			res.Fault = &Fault{Seq: r.Seq, Reason: "chain_prev does not link to the prior chain_hash"}
			return res
		}
		if got := HashRecord(Canonical(r), r.ChainPrev); !bytes.Equal(got, r.ChainHash) {
			res.Fault = &Fault{Seq: r.Seq, Reason: "chain_hash does not match the canonical row"}
			return res
		}
		prev = r.ChainHash
		res.Records++
		res.HeadSeq = r.Seq
		res.HeadHash = r.ChainHash
	}
	return res
}
