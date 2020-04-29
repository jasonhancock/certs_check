package main

import (
	"crypto/tls"
	"flag"
	"log"
	"strings"
	"time"

	slack "github.com/ashwanthkumar/slack-go-webhook"
	"github.com/dustin/go-humanize"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
)

func main() {
	var (
		hosts           = flag.String("hosts", "", "comma-delimited list of hosts")
		slackWebhookURL = flag.String("webhook-url", "", "slack webhook url")
		threshold       = flag.Duration("threshold", 7*24*time.Hour, "When to issue warnings. Accepts a time.Duration")
	)

	var fields []*slack.Field

	for _, host := range strings.Split(*hosts, ",") {
		if err := checkHost(host, *threshold); err != nil {
			fields = append(fields, &slack.Field{
				Title: host,
				Value: err.Error(),
			})
		}
	}

	if len(fields) == 0 {
		return
	}

	color := "#ff0000"
	payload := slack.Payload{
		Text: "Certificate Check Errors",
		Attachments: []slack.Attachment{
			{
				Color:  &color,
				Fields: fields,
			},
		},
	}

	// slack package returns a slice of errors. Convert into a multierror
	if errs := slack.Send(*slackWebhookURL, "", payload); len(errs) > 0 {
		var retErrs error
		for _, v := range errs {
			retErrs = multierror.Append(retErrs, v)
		}
		log.Fatal(errors.Wrap(retErrs, "sending slack notification"))
	}
}

func checkHost(host string, duration time.Duration) error {
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		for _, cert := range chain {
			checkedCerts[string(cert.Signature)] = struct{}{}

			if time.Now().Add(duration).After(cert.NotAfter) {
				return errors.Errorf("%s certificate expires in %s", cert.Subject.CommonName, humanize.Time(cert.NotAfter))
			}
		}
	}

	return nil
}
