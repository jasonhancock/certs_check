package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	slack "github.com/jasonhancock/slack-go-webhook"
)

func main() {
	var (
		hosts           = flag.String("hosts", "", "comma-delimited list of hosts")
		slackWebhookURL = flag.String("webhook-url", "", "slack webhook url")
		threshold       = flag.Duration("threshold", 7*24*time.Hour, "When to issue warnings. Accepts a time.Duration")
	)
	flag.Parse()

	if len(strings.Split(*hosts, ",")) == 0 {
		log.Fatal("no hosts specified")
	}

	if *slackWebhookURL == "" {
		log.Fatal("webhook-url not specified")
	}

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
	if err := slack.Send(*slackWebhookURL, "", payload); err != nil {
		log.Fatal(fmt.Errorf("sending slack notification: %w", err))
	}
}

func checkHost(host string, duration time.Duration) error {
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			if time.Now().Add(duration).After(cert.NotAfter) {
				return fmt.Errorf("%s certificate expires in %s", cert.Subject.CommonName, humanize.Time(cert.NotAfter))
			}
		}
	}

	return nil
}
