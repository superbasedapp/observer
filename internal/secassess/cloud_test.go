package secassess

import "testing"

func TestClassifyCloudCommand(t *testing.T) {
	cases := []struct {
		line string
		want CloudClass
	}{
		// aws: the operation is the second word.
		{"aws ec2 describe-instances --region eu-west-1", CloudReadOnly},
		{"aws s3api list-buckets", CloudReadOnly},
		{"aws iam get-account-summary --profile dev", CloudReadOnly},
		{"aws sts get-caller-identity", CloudReadOnly},
		{"aws s3 ls", CloudReadOnly},
		{"aws --profile prod --region us-east-1 ec2 describe-security-groups", CloudReadOnly},
		{"aws ec2 terminate-instances --instance-ids i-1", CloudMutating},
		{"aws s3 rm s3://b/k", CloudMutating},
		{"aws iam create-user --user-name x", CloudMutating},
		{"aws s3 cp a s3://b/a", CloudMutating},
		{"aws secretsmanager get-secret-value --secret-id x", CloudSecretMaterial},
		{"aws secretsmanager list-secrets", CloudReadOnly},
		{"aws ssm get-parameter --name x --with-decryption", CloudSecretMaterial},
		{"aws kms decrypt --ciphertext-blob x", CloudSecretMaterial},
		{"aws ecr get-login-password", CloudSecretMaterial},
		{"aws sts get-session-token", CloudSecretMaterial},
		{"aws frobnicate", CloudUnknown},
		// az: the last word that is a verb.
		{"az vm list -g rg", CloudReadOnly},
		{"az storage account show --name sa", CloudReadOnly},
		{"az group delete -n rg --yes", CloudMutating},
		{"az role assignment create --assignee x", CloudMutating},
		{"az keyvault secret show --name s --vault-name v", CloudSecretMaterial},
		{"az account get-access-token", CloudSecretMaterial},
		// gcloud
		{"gcloud compute instances list --project p", CloudReadOnly},
		{"gcloud compute instances describe vm1 --zone z", CloudReadOnly},
		{"gcloud projects get-iam-policy p", CloudReadOnly},
		{"gcloud compute instances delete vm1", CloudMutating},
		{"gcloud projects add-iam-policy-binding p --member m --role r", CloudMutating},
		{"gcloud config set project x", CloudMutating},
		{"gcloud auth print-access-token", CloudSecretMaterial},
		{"gcloud secrets versions access latest --secret s", CloudSecretMaterial},
		// kubectl
		{"kubectl get pods -n kube-system", CloudReadOnly},
		{"kubectl --context c describe node n", CloudReadOnly},
		{"kubectl config view", CloudReadOnly},
		{"kubectl auth can-i list pods", CloudReadOnly},
		{"kubectl apply -f x.yaml", CloudMutating},
		{"kubectl delete pod p", CloudMutating},
		{"kubectl exec -it p -- sh", CloudMutating},
		{"kubectl config use-context other", CloudMutating},
		{"kubectl get secret s -o yaml", CloudSecretMaterial},
		// terraform
		{"terraform validate", CloudReadOnly},
		{"terraform plan -out p", CloudReadOnly},
		{"terraform apply", CloudMutating},
		{"terraform destroy", CloudMutating},
		// shapes Observer cannot read
		{"aws ec2 describe-instances; aws ec2 terminate-instances --instance-ids i-1", CloudUnknown},
		{"aws ec2 describe-instances && rm -rf x", CloudUnknown},
		{"aws s3 ls > out.txt", CloudUnknown},
		{"echo $(aws sts get-caller-identity)", CloudUnknown},
		{"aws ec2 describe-instances | sh", CloudUnknown},
		{"terraform", CloudUnknown},
		{"ls -la", CloudUnknown},
		// a pipe into a reader keeps the left side's class
		{"aws ec2 describe-instances | jq .Reservations", CloudReadOnly},
		{"AWS_PROFILE=dev aws ec2 describe-vpcs", CloudReadOnly},
		{"sudo kubectl get nodes", CloudReadOnly},
		{"/usr/local/bin/aws.exe ec2 describe-vpcs", CloudReadOnly},
		// not lines
		{"", ""},
		{"   ", ""},
		{"# a comment", ""},
	}
	for _, tc := range cases {
		if got := ClassifyCloudCommand(tc.line); got != tc.want {
			t.Errorf("%q = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestCountCloudCommands(t *testing.T) {
	body := "# header\naws ec2 describe-instances\naws s3 ls\n\naws ec2 terminate-instances --instance-ids i\naws secretsmanager get-secret-value --secret-id x\nweirdtool run\n"
	c := CountCloudCommands(body)
	if c.ReadOnly != 2 || c.Mutating != 1 || c.SecretMaterial != 1 || c.Unknown != 1 || c.Total() != 5 {
		t.Fatalf("counts = %+v", c)
	}
	if !c.Crossed() {
		t.Error("a list with a mutating command did not cross")
	}
	if (CloudCounts{ReadOnly: 3, Unknown: 2}).Crossed() {
		t.Error("read-only and unknown lines crossed")
	}
}
