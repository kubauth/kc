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

package misc

import (
	"fmt"
	"os"
)

func SafeBoolPtr(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func ShortenString(str string) string {
	if len(str) <= 30 {
		return str
	} else {
		return fmt.Sprintf("%s.......%s", str[:10], str[len(str)-10:])
	}
}

func EnsureDir(dirName string) error {
	st, err := os.Stat(dirName)
	if err != nil {
		// We consider it is a file not found
		err = os.MkdirAll(dirName, 0700)
		if err != nil {
			return err
		}
		return nil
	}
	if !st.IsDir() {
		return fmt.Errorf("path '%s' is a file. We need this to be a folder", dirName)
	}
	return nil
}
