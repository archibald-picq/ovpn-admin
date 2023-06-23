package shell

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func ReadFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading file %v", err)
		return ""
	}

	return string(content)
}

func FileExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatalf("fExist: %s", err)
		return false
	}

	return true
}

func dirname(path string) string {
	if strings.HasSuffix("/", path) {
		//log.Printf("referencePath ends with '/': '%s' .. '%s'", path, relativePath)
		return path
	}
	p := strings.LastIndex(path, "/")
	return path[0 : p+1]
}

func AbsolutizePath(referencePath string, relativePath string) string {
	if strings.HasPrefix(relativePath, "/") {
		return relativePath
	}
	relativePath = strings.TrimPrefix(relativePath, "./")

	referencePath = dirname(referencePath)

	//log.Printf("concat paths: '%s' .. '%s'", referencePath, relativePath)
	return referencePath + relativePath
}

func WriteFile(path string, content string) error {
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func FileCopy(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories, symlinks, devices, etc.)
		return fmt.Errorf("fCopy: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("fCopy: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return err
		}
	}
	if err = os.Link(src, dst); err == nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}
