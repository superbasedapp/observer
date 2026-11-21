package secassess

import "testing"

// TestModelContractsTable: the table that goes from a contract to its schema and
// back is one table, every kind with a model file is a row of it, and a schema
// word the table does not hold is no contract.
func TestModelContractsTable(t *testing.T) {
	seenContract, seenSchema := map[Contract]bool{}, map[string]bool{}
	for _, m := range ModelContracts {
		if seenContract[m.Contract] || seenSchema[m.Schema] {
			t.Errorf("a repeated row: %+v", m)
		}
		seenContract[m.Contract], seenSchema[m.Schema] = true, true
		if m.Schema == "" || m.Contract.Schema() != m.Schema {
			t.Errorf("%s: Schema() = %q, want %q", m.Contract, m.Contract.Schema(), m.Schema)
		}
		if got, ok := ContractOfSchema(m.Schema); !ok || got != m.Contract {
			t.Errorf("%s: ContractOfSchema = %q, %v", m.Schema, got, ok)
		}
	}
	for _, k := range Kinds() {
		if !k.ModelContract() {
			continue
		}
		if !seenContract[k.Contract] {
			t.Errorf("kind %s writes the contract %s, which is not a row of ModelContracts", k.ID, k.Contract)
		}
	}
	for _, s := range []string{"", "other.v1", "observer.pentest.v2", "Observer.Pentest.V1"} {
		if c, ok := ContractOfSchema(s); ok || c != "" {
			t.Errorf("ContractOfSchema(%q) = %q, %v", s, c, ok)
		}
	}
	if ContractSARIF.Schema() != "" || Contract("").Schema() != "" {
		t.Error("a contract without a model file names a schema")
	}
}
