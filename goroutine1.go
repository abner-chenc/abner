package main

import (
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"time"
)

const chan_nums int = 2000000

func Create_threads() {
	log.Println("Create thread")
	ch := make(chan int, chan_nums)
	add := func() {
		for {
			select {
			case i := <-ch:
				i += 1
			}
		}
	}

	for i := 0; i < chan_nums; i++ {
		go add()
	}

	t1 := time.Now()
	for {
		for i := 0; i < chan_nums; i++ {
			ch <- rand.Int()
		}

		time.Sleep(time.Millisecond * 5)
		t2 := time.Now()

		if t2.Sub(t1).Seconds() > 10 {
			log.Println(" thread is running...")
			t1 = t2
		}
	}
}

func main() {
	go Create_threads()
	log.Fatal(http.ListenAndServe("0.0.0.0:6365", nil))

}
