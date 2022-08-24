package logger

import (
	"os"
	"strings"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Logger
	Log *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}
	NfName := ParseNfName(os.Args[0])
	Log = log.WithFields(logrus.Fields{"component": "ONVM", "category": NfName})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(enable bool) {
	log.SetReportCaller(enable)
}

func ParseNfName(args string) string {
	nfName := strings.Split(args, "/")
	return nfName[1]
}
