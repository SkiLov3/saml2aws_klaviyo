package browser

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	//need to fix reference here
	"github.com/pkg/browser"
	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

// Client client for browser based Identity Provider
type Client struct {
	Headless bool
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		Headless: idpAccount.Headless,
	}, nil
}

func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	// Validate loginDetails
	if err := cl.Validate(loginDetails); err != nil {
		return "", err
	}

	logger.WithField("URL", loginDetails.URL).Info("opening system default browser")

	// Open the URL in the system's default browser
	err := browser.OpenURL(loginDetails.URL)
	if err != nil {
		return "", err
	}

	// TODO: Implement logic to retrieve SAMLResponse from the opened browser.

	return "", nil
} //-nik stopped here

var getSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails) (string, error) {
	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	signin_re, err := signinRegex()
	if err != nil {
		return "", err
	}

	fmt.Println("waiting ...")
	r, _ := page.WaitForRequest(signin_re)
	data, err := r.PostData()
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

func signinRegex() (*regexp.Regexp, error) {
	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	return regexp.Compile(`https:\/\/((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))\/saml`)
}

func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {

	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}

	return nil
}
