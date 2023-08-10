package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/panjf2000/ants/v2"
)

var count = 0

func greeting(i int) func() {
	return func() {
		time.Sleep(1 * time.Second)
		count++
		fmt.Printf("hello world: %d, goroutine_num: %d\n", i, runtime.NumGoroutine())
	}
}

func main() {
	fmt.Println("start goroutine: ", runtime.NumGoroutine())
	p, _ := ants.NewPool(5)
	fmt.Println("first p.Running(): ", p.Running())
	defer p.Release()

	for i := 0; i < 20; i++ {
		index := i
		p.Submit(greeting(index))
	}

	fmt.Println("later p.Running(): ", p.Running())
	fmt.Println("end goroutine: ", runtime.NumGoroutine())
	fmt.Println("count: ", count)
	for {
		time.Sleep(1 * time.Second)
	}
}
