package cycletls

import (
	"math/rand"
	"strings"
	"time"
)

// resolveBrowserFingerprint materializes the original random policies for one
// transport generation. Its result must never be used to identify the pool.
func resolveBrowserFingerprint(browser Browser) Browser {
	if browser.JA3 != "RAND" && browser.SignatureAlgorithms != "RAND" && !browser.ShuffleExtensions {
		return browser
	}
	rr := rand.New(rand.NewSource(time.Now().UnixNano()))
	if browser.JA3 == "RAND" {
		browser.JA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2"
		for _, item := range []string{"-30-", "-25-", "-49-", "-256-", "-257-", "-258-", "-259-", "-103-", "-107-", "-156-", "-157-", "-158-", "-159-"} {
			if rr.Intn(2) == 0 {
				browser.JA3 = strings.ReplaceAll(browser.JA3, item, "-")
			}
		}
		for _, item := range []string{"-21,", "-260,"} {
			if rr.Intn(2) == 0 {
				browser.JA3 = strings.ReplaceAll(browser.JA3, item, ",")
			}
		}
	}
	if browser.SignatureAlgorithms == "RAND" {
		sigAlgs := strings.Split("0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602", ",")
		rr.Shuffle(len(sigAlgs), func(i, j int) { sigAlgs[i], sigAlgs[j] = sigAlgs[j], sigAlgs[i] })
		browser.SignatureAlgorithms = strings.Join(sigAlgs, ",")
	}
	if browser.JA3 != "" && browser.ShuffleExtensions {
		parts := strings.Split(browser.JA3, ",")
		if len(parts) >= 4 {
			extensions := strings.Split(parts[2], "-")
			rr.Shuffle(len(extensions), func(i, j int) {
				if extensions[i] != "41" && extensions[j] != "41" {
					extensions[i], extensions[j] = extensions[j], extensions[i]
				}
			})
			parts[2] = strings.Join(extensions, "-")
			browser.JA3 = strings.Join(parts, ",")
		}
	}
	return browser
}
