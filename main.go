package main

import (
	"bufio"
	"fmt"
	"github.com/yegamble/tryte-crypt-go/cmd"
	"github.com/yegamble/tryte-crypt-go/handler"
	"os"
	"strings"
)

func main() {

	buf := bufio.NewReader(os.Stdin)

	fmt.Print("Do you want start server mode? (Y/n) ")
	selection, err := buf.ReadBytes('\n')
	if err != nil {
		main()
	}

	selectionString := strings.TrimSuffix(string(selection), "\n")
	if strings.ToLower(selectionString) == "y" {
		handler.SetRoutes()
	} else {
		cmd.MainCMD()
	}
}
