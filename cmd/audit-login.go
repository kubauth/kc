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

var auditLoginCmd = &cobra.Command{
	Use:   "logins",
	Short: "List/fetch login operations",
	Args:  cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {

		err := func() error {

			k8sClient, err := k8sapi.GetKubeClient(scheme)
			if err != nil {
				return fmt.Errorf("unable to setup k8s client: %w", err)
			}
			var selector = client.MatchingLabels{}
			if len(args) > 0 {
				selector = client.MatchingLabels{
					"kubauth.kubotal.io/login": args[0],
				}
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
			tw := new(tabwriter.Writer)
			tw.Init(os.Stdout, 2, 4, 3, ' ', 0)
			twb := misc.NewTabWriterBuffer(tw)
			for _, attempt := range list.Items {
				if len(args) == 0 || attempt.Spec.User.Login == args[0] {
					addLine(twb, attempt)
				}
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

func addLine(twb misc.TabWriterBuffer, attempt kubauthv1alpha1.LoginAttempt) {
	claims, err := json.Marshal(attempt.Spec.User.Claims)
	if err != nil {
		claims = []byte("!!! Unable to decode !!!")
	}
	uid := "UNSET"
	if attempt.Spec.User.Uid != nil {
		uid = strconv.Itoa(*attempt.Spec.User.Uid)
	}
	twb.Add("WHEN", "%s", attempt.Spec.When.Format("Mon 15:04:05"))
	twb.Add("LOGIN", "%s", attempt.Spec.User.Login)
	twb.Add("STATUS", "%s", attempt.Spec.Status)
	twb.Add("UID", "%s", uid)
	twb.Add("NAME", "%s", attempt.Spec.User.Name)
	twb.Add("GROUPS", "[%s]", strings.Join(attempt.Spec.User.Groups, ","))
	twb.Add("CLAIMS", "%s", string(claims))
	twb.Add("EMAILS", "[%s]", strings.Join(attempt.Spec.User.Emails, ","))
	twb.Add("AUTH", "%s", attempt.Spec.Authority)
	twb.EndOfLine()

}
