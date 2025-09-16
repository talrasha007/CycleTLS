package tests

import (
	"fmt"
	"testing"

	cycletls "github.com/talrasha007/CycleTLS"
)

func TestSomething(t *testing.T) {
	url := "https://tls.peet.ws/api/all"
	url = "https://d27tmy7atbm8yh.cloudfront.net/"
	client := cycletls.Init()
	defer client.Close() // Ensure resources are cleaned up

	for i := 0; i < 2; i++ {
		resp, err := client.Do(url, cycletls.Options{
			Body:                     "",
			EnableClientSessionCache: true,
			// SignatureAlgorithms:      "0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602",
			// Ja3:                      "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-41,29-23-24,0",

			// Chrome 140
			SignatureAlgorithms: "0403,0804,0401,0503,0805,0501,0806,0601",
			Ja3:                 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-27-35-65037-17613-23-5-0-10-13-11-43-45-16-65281-18-41,29-23-24-25,0",
			UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36",
		}, "GET")

		if err != nil {
			t.Fatal("Request Failed: " + err.Error())
		}

		fmt.Println(resp.Body)

	}
}
