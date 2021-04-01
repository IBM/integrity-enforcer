package main

import (
	"fmt"

	"github.com/IBM/integrity-enforcer/inspector/pkg/inspector"
)

func main() {
	insp := inspector.NewInspector()
	err := insp.Init()
	if err != nil {
		fmt.Println("Failed to initialize Inspector; err: ", err.Error())
		return
	}

	insp.Run()
}
