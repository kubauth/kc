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
