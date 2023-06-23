package shell

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
)

func RunBash(script string) (string, error) {
	log.Printf(script)
	cmd := exec.Command("bash", "-c", script)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprint(err) + " : " + string(stdout), errors.New(fmt.Sprint(err) + " : " + string(stdout))
	}
	return string(stdout), err
}
