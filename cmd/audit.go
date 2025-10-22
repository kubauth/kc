package cmd

import (
	kubauthv1alpha1 "github.com/kubauth/kubauth/api/kubauth/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var auditParams struct {
	namespace string
}

var (
	scheme = runtime.NewScheme()
)

func init() {

	auditCmd.PersistentFlags().StringVarP(&auditParams.namespace, "namespace", "n", "kubauth-audit", "Audit namespace")

	auditCmd.AddCommand(auditLoginCmd)
	auditCmd.AddCommand(auditDetailCmd)

	utilruntime.Must(kubauthv1alpha1.AddToScheme(scheme))

}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "audit commands",
}
