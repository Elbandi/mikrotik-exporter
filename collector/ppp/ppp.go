package ppp

import (
	"fmt"
	"github.com/ogi4i/mikrotik-exporter/parsers"
	log "github.com/sirupsen/logrus"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/routeros.v2/proto"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties        = []string{"name", "address", "caller-id", "service", "comment", "uptime"}
	metricDescription = metrics.BuildMetricDescription(prefix, "uptime", "ppp client uptime in seconds",
		[]string{"name", "address", "peer_name", "peer_address", "caller_id", "service", "comment"},
	)
)

const prefix = "ppp"

type pppCollector struct{}

func NewCollector() *pppCollector {
	return &pppCollector{}
}

func (c *pppCollector) Name() string {
	return prefix
}

func (c *pppCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *pppCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch ppp: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *pppCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ppp/active/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *pppCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	value := re.Map["uptime"]
	if len(value) == 0 {
		return
	}

	v, err := parsers.ParseDuration(value)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  "uptime",
			"value":     value,
			"error":     err,
		}).Error("error parsing duration metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescription, prometheus.CounterValue, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["name"], re.Map["address"], re.Map["caller-id"], re.Map["service"], re.Map["comment"],
	)
}
