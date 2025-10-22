/*
Copyright 2025 Kubotal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
