//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"errors"

	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// connect_request_cloud.go is the connect request seam in a build with Cloud
// Intelligence: POST /v1/connect/requests and GET /v1/connect/requests/{id}
// through the consent gateway's Bootstrap family (ledger row ONB-5). No
// consent source is passed: the user's own `observer connect` is the
// authorization, as for sign-in (R2 F10). The base URL resolves exactly as
// `observer cloud login` resolves it. This file maps the gateway's types and
// errors onto connect_request.go's plain ones, so the flow itself never
// imports the network lane.

func defaultConnectRequestSeams() connectRequestSeams {
	return connectRequestSeams{
		start: func(ctx context.Context, o connectCloudOpts, in connectRequestInput) (connectRequestInfo, error) {
			gw, err := openConnectGateway(o)
			if err != nil {
				return connectRequestInfo{}, err
			}
			r, err := gw.BootstrapConnectStart(ctx, cloudgateway.ConnectRequestInput{
				MachineName: in.MachineName, OS: in.OS, Arch: in.Arch,
				ObserverVersion: in.ObserverVersion, TargetHint: in.TargetHint,
			})
			if errors.Is(err, cloudgateway.ErrConnectUnsupported) {
				return connectRequestInfo{}, errConnectUnsupported
			}
			if err != nil {
				return connectRequestInfo{}, err
			}
			return connectRequestInfo{
				RequestID: r.RequestID, UserCode: r.UserCode, ApproveURL: r.ApproveURL,
				VerifyURL: r.VerifyURL, ExpiresIn: r.ExpiresIn, Interval: r.Interval,
			}, nil
		},
		poll: func(ctx context.Context, o connectCloudOpts, requestID string) (connectApproval, error) {
			gw, err := openConnectGateway(o)
			if err != nil {
				return connectApproval{}, err
			}
			st, err := gw.BootstrapConnectPoll(ctx, requestID)
			switch {
			case errors.Is(err, cloudgateway.ErrConnectRequestGone):
				return connectApproval{}, errConnectRequestGone
			case errors.Is(err, cloudgateway.ErrConnectSlowDown):
				return connectApproval{}, errConnectSlowDown
			case err != nil:
				return connectApproval{}, err
			}
			ap := connectApproval{
				Status: st.Status, ConsentReceiptID: st.ConsentReceiptID, SignedIn: st.SignedIn,
				EnrolCode: st.EnrolCode, AttachGrant: st.AttachGrant,
			}
			if t := st.Target; t != nil {
				ap.Target = &connectTargetInfo{
					OrgID: t.OrgID, Slug: t.Slug, Kind: t.Kind, DisplayName: t.DisplayName,
					ShareLevel: t.ShareLevel, ServerURL: t.ServerURL, DashboardURL: t.DashboardURL,
				}
			}
			return ap, nil
		},
		onlineBase: func(o connectCloudOpts) string {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: o.configPath})
			if err != nil {
				return resolveCloudBaseURL(o.baseURL, config.Config{})
			}
			return resolveCloudBaseURL(o.baseURL, cfg)
		},
	}
}

// defaultAttachProver is the attach grant's device-proof signer in a build
// with Cloud Intelligence (Getting started v2 lane 8): this machine's cloud
// device key, opened through the consent gateway like the connect request
// itself (no network call; the person's own Connect approval is the
// authorization). The device key signs only the grant and the node key the
// enrolment generates.
func defaultAttachProver() func(configPath string) func(grant, agentPublicKey string) (orgcontract.AttachProof, error) {
	return func(configPath string) func(grant, agentPublicKey string) (orgcontract.AttachProof, error) {
		return func(grant, agentPublicKey string) (orgcontract.AttachProof, error) {
			gw, err := openConnectGateway(connectCloudOpts{configPath: configPath})
			if err != nil {
				return orgcontract.AttachProof{}, err
			}
			p, err := gw.BootstrapAttachProof(grant, agentPublicKey)
			if err != nil {
				return orgcontract.AttachProof{}, err
			}
			return orgcontract.AttachProof{DevicePublicKey: p.DevicePublicKey, Signature: p.Signature}, nil
		}
	}
}
