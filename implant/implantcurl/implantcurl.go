package implantcurl

import (
	"io/ioutil"
	"net/http"
)

func Curl(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return err.Error()
	}
	//We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err.Error()
	}
	//Convert the body to type string
	sb := string(body)
	return sb
}
