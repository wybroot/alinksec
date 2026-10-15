// A valid native Go executable which fails before Agent/service initialization.
package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stderr, "intentional native upgrade startup failure"); os.Exit(1) }
