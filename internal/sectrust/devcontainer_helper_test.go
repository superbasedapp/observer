package sectrust

import "github.com/marmutapp/superbased-observer/internal/sandboxoci"

// ociDevcontainer is the container driver's parser as the cmd layer injects
// it (tests only: the package itself never imports the driver).
func ociDevcontainer(data []byte) ([]string, map[string]string, error) {
	d, err := sandboxoci.ParseDevcontainer(data)
	return d.Ignored, d.IgnoredRaw, err
}
