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
	"context"
	"encoding/json"
	"fmt"
	"kc/internal/k8sapi"
	"kc/internal/misc"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	kubauthv1alpha1 "github.com/kubauth/kubauth/api/kubauth/v1alpha1"
	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var auditDetailCmd = &cobra.Command{
	Use:   "detail",
	Short: "Detail last login of user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := func() error {

			k8sClient, err := k8sapi.GetKubeClient(scheme)
			if err != nil {
				return fmt.Errorf("unable to setup k8s client: %w", err)
			}
			selector := client.MatchingLabels{
				"kubauth.kubotal.io/login": args[0],
			}
			list := &kubauthv1alpha1.LoginAttemptList{}
			err = k8sClient.List(context.Background(), list, selector)
			if err != nil {
				return fmt.Errorf("unable to list loginAttempts: %w", err)
			}
			if len(list.Items) == 0 {
				fmt.Println("No loginAttempts found")
				return nil
			}
			// -------------------- Lookup last attempt
			lastAttempt := list.Items[0]
			for _, attempt := range list.Items {
				if attempt.Spec.When.After(lastAttempt.Spec.When.Time) {
					lastAttempt = attempt
				}
			}
			tw := new(tabwriter.Writer)
			tw.Init(os.Stdout, 2, 4, 3, ' ', 0)
			twb := misc.NewTabWriterBuffer(tw)
			addLine(twb, lastAttempt, false)
			_ = tw.Flush()
			fmt.Printf("Detail:\n")
			tw = new(tabwriter.Writer)
			tw.Init(os.Stdout, 2, 4, 3, ' ', 0)
			twb = misc.NewTabWriterBuffer(tw)
			for _, detail := range lastAttempt.Spec.Details {
				claims, err := json.Marshal(detail.Translated.Claims)
				if err != nil {
					claims = []byte("!!! Unable to decode !!!")
				}
				uid := "-"
				if detail.User.Uid != nil {
					uid = strconv.Itoa(*detail.User.Uid)
				}
				twb.Add("PROVIDER", "%s", detail.Provider.Name)
				if detail.Provider.CredentialAuthority {
					twb.Add("STATUS", "%s", detail.Status)
					twb.Add("UID", "%s", uid)
				} else {
					twb.Add("STATUS", "%s", "N/A")
					twb.Add("UID", "%s", "N/A")
				}
				if detail.Provider.NameAuthority {
					twb.Add("NAME", "%s", detail.User.Name)
				} else {
					twb.Add("NAME", "%s", "N/A")
				}
				if detail.Provider.GroupAuthority {
					twb.Add("GROUPS", "%s", fmt.Sprintf("[%s]", strings.Join(detail.Translated.Groups, ",")))
				} else {
					twb.Add("GROUPS", "%s", "N/A")
				}
				if detail.Provider.ClaimAuthority {
					twb.Add("CLAIMS", "%s", string(claims))
				} else {
					twb.Add("CLAIMS", "%s", "N/A")
				}
				if detail.Provider.EmailAuthority {
					twb.Add("EMAILS", "%s", fmt.Sprintf("[%s]", strings.Join(detail.User.Emails, ",")))
				} else {
					twb.Add("EMAILS", "%s", "N/A")
				}
				twb.EndOfLine()
			}
			_ = tw.Flush()
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}

	},
}
